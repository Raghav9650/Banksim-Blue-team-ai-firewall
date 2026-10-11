-- BankSim account isolation and encrypted audit schema.
-- Run this entire script in Supabase Dashboard -> SQL Editor as the project owner.

create schema if not exists extensions;
create extension if not exists "uuid-ossp" with schema extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.bank_users (
  uuid uuid primary key references auth.users (id) on delete cascade
    default extensions.uuid_generate_v4(),
  clear_name text not null,
  account_number text not null unique
    default ('BS-' || upper(substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 10))),
  balance numeric(14, 2) not null default 0
    check (balance >= 0),
  clearance_level text not null default 'STANDARD',
  encryption_salt text not null,
  key_verification text
);

-- This is a separate, simulation-only double-entry ledger. It never connects to a payment rail.
create table if not exists public.banksim_simulated_transactions (
  transaction_id uuid primary key default extensions.uuid_generate_v4(),
  reference text not null,
  account_owner_id uuid not null references auth.users (id) on delete cascade,
  transaction_type text not null
    check (transaction_type in ('DEPOSIT', 'TRANSFER_DEBIT', 'TRANSFER_CREDIT')),
  amount numeric(14, 2) not null check (amount > 0),
  counterparty_account text not null,
  memo text not null default '',
  balance_after numeric(14, 2) not null check (balance_after >= 0),
  idempotency_key uuid,
  created_at timestamptz not null default now()
);

create unique index if not exists banksim_simulated_transactions_reference_idx
  on public.banksim_simulated_transactions (reference, transaction_type, account_owner_id);
create unique index if not exists banksim_simulated_transactions_idempotency_idx
  on public.banksim_simulated_transactions (account_owner_id, transaction_type, idempotency_key)
  where idempotency_key is not null;
create index if not exists banksim_simulated_transactions_owner_time_idx
  on public.banksim_simulated_transactions (account_owner_id, created_at desc);

create table if not exists public.banksim_firewall_logs (
  log_id uuid primary key default extensions.uuid_generate_v4(),
  user_id uuid not null references auth.users (id) on delete cascade,
  "timestamp" timestamptz not null default now(),
  incoming_prompt text not null,
  target_tool text not null
    check (target_tool in ('BALANCE_CHECK', 'TRANSFER_SIMULATION', 'MEMO_REVIEW')),
  firewall_status text not null
    check (firewall_status in ('APPROVED', 'BLOCKED')),
  risk_score numeric(5, 4) not null
    check (risk_score >= 0 and risk_score <= 1),
  threat_category text not null
    check (threat_category in (
      'PROMPT_INJECTION',
      'JAILBREAK',
      'ROLEPLAY_ATTACK',
      'MEMO_INJECTION',
      'STRUCTURAL_ANOMALY',
      'NONE'
    )),
  engine_explanation text not null,
  sanitized_payload text,
  signals jsonb not null,
  compliance_hash text not null
    check (compliance_hash ~ '^[0-9a-f]{64}$'),
  latency_ms integer not null check (latency_ms >= 0)
);

create index if not exists banksim_firewall_logs_user_timestamp_idx
  on public.banksim_firewall_logs (user_id, "timestamp" desc);
create index if not exists banksim_firewall_logs_status_idx
  on public.banksim_firewall_logs (user_id, firewall_status);
create index if not exists banksim_firewall_logs_category_idx
  on public.banksim_firewall_logs (user_id, threat_category);

alter table public.bank_users enable row level security;
alter table public.banksim_simulated_transactions enable row level security;
alter table public.banksim_firewall_logs enable row level security;

-- Profiles are created by the trusted auth trigger. An owner can only read their profile
-- and write the password-check ciphertext; balance/clearance/account identity remain server-owned.
revoke all on public.bank_users from anon, authenticated;
grant usage on schema extensions to service_role;
grant execute on function extensions.uuid_generate_v4() to service_role;
grant select (uuid, clear_name, account_number, clearance_level, encryption_salt, key_verification)
  on public.bank_users to authenticated;
grant update (key_verification) on public.bank_users to authenticated;
grant select (uuid, account_number, balance) on public.bank_users to service_role;

revoke all on public.banksim_simulated_transactions from anon, authenticated, service_role;
grant select on public.banksim_simulated_transactions to service_role;
drop policy if exists banksim_simulated_transactions_select_own on public.banksim_simulated_transactions;
create policy banksim_simulated_transactions_select_own
  on public.banksim_simulated_transactions
  for select
  to service_role
  using ((select auth.uid()) = account_owner_id);

drop policy if exists banksim_users_select_own_profile on public.bank_users;
create policy banksim_users_select_own_profile
  on public.bank_users
  for select
  to authenticated
  using ((select auth.uid()) = uuid);

drop policy if exists banksim_users_update_own_key_check on public.bank_users;
create policy banksim_users_update_own_key_check
  on public.bank_users
  for update
  to authenticated
  using ((select auth.uid()) = uuid)
  with check ((select auth.uid()) = uuid);

-- The browser may read only its own rows. It cannot add, revise, or remove audit records.
revoke all on public.banksim_firewall_logs from anon, authenticated;
grant select on public.banksim_firewall_logs to authenticated;
drop policy if exists banksim_logs_select_own_rows on public.banksim_firewall_logs;
create policy banksim_logs_select_own_rows
  on public.banksim_firewall_logs
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

-- The server service key writes rows with the verified auth user id. No browser role has write access.
revoke all on public.banksim_firewall_logs from service_role;
grant select, insert on public.banksim_firewall_logs to service_role;
revoke update, delete, truncate on public.banksim_firewall_logs
  from anon, authenticated, service_role;

create or replace function public.banksim_reject_firewall_log_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  raise exception 'BankSim firewall audit records are append-only.';
end;
$$;

drop trigger if exists banksim_firewall_logs_no_row_mutation on public.banksim_firewall_logs;
create trigger banksim_firewall_logs_no_row_mutation
  before update or delete on public.banksim_firewall_logs
  for each row execute function public.banksim_reject_firewall_log_mutation();

drop trigger if exists banksim_firewall_logs_no_truncate on public.banksim_firewall_logs;
create trigger banksim_firewall_logs_no_truncate
  before truncate on public.banksim_firewall_logs
  for each statement execute function public.banksim_reject_firewall_log_mutation();
revoke execute on function public.banksim_reject_firewall_log_mutation()
  from public, anon, authenticated, service_role;

-- Every email/password signup receives a private audit salt and one private profile row.
-- The SQL trigger never generates or stores a reusable decryption key.
create or replace function public.banksim_create_user_profile()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
begin
  insert into public.bank_users (uuid, clear_name, encryption_salt)
  values (
    new.id,
    coalesce(
      nullif(new.raw_user_meta_data ->> 'clear_name', ''),
      nullif(split_part(coalesce(new.email, ''), '@', 1), ''),
      'BankSim User'
    ),
    encode(extensions.gen_random_bytes(16), 'hex')
  )
  on conflict (uuid) do nothing;
  return new;
end;
$$;

drop trigger if exists banksim_auth_user_profile on auth.users;
create trigger banksim_auth_user_profile
  after insert on auth.users
  for each row execute function public.banksim_create_user_profile();
revoke execute on function public.banksim_create_user_profile()
  from public, anon, authenticated;
grant execute on function public.banksim_create_user_profile()
  to supabase_auth_admin;

-- Deposit only into the caller's server-verified simulation account; replay keys prevent retries
-- from crediting the same simulated deposit more than once.
create or replace function public.banksim_simulated_deposit(
  p_owner_id uuid,
  p_amount numeric,
  p_idempotency_key uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  owner_account_number text;
  owner_balance numeric(14, 2);
  existing_reference text;
  posted_reference text;
begin
  if p_amount is null or p_amount <= 0 or p_amount > 5000 or p_amount <> round(p_amount, 2) then
    raise exception 'SIMULATED_INVALID_AMOUNT';
  end if;
  if p_idempotency_key is null then
    raise exception 'SIMULATED_INVALID_IDEMPOTENCY_KEY';
  end if;

  select account_number, balance
    into owner_account_number, owner_balance
    from public.bank_users
    where uuid = p_owner_id
    for update;
  if not found then
    raise exception 'SIMULATED_ACCOUNT_NOT_FOUND';
  end if;

  select reference into existing_reference
    from public.banksim_simulated_transactions
    where account_owner_id = p_owner_id
      and transaction_type = 'DEPOSIT'
      and idempotency_key = p_idempotency_key;
  if found then
    return jsonb_build_object('reference', existing_reference, 'balance', owner_balance);
  end if;

  posted_reference := 'SIM-' || upper(substr(encode(extensions.gen_random_bytes(8), 'hex'), 1, 12));
  update public.bank_users
    set balance = balance + p_amount
    where uuid = p_owner_id
    returning balance into owner_balance;

  insert into public.banksim_simulated_transactions (
    reference, account_owner_id, transaction_type, amount,
    counterparty_account, memo, balance_after, idempotency_key
  ) values (
    posted_reference, p_owner_id, 'DEPOSIT', p_amount,
    'SIMULATED CASH DEPOSIT', 'Simulated cash deposit', owner_balance, p_idempotency_key
  );

  return jsonb_build_object('reference', posted_reference, 'balance', owner_balance);
end;
$$;

-- Both account rows and both matching ledger entries change in one database transaction.
-- Drop the earlier p_memo signature before recreating it with p_encrypted_memo;
-- PostgreSQL cannot rename an input parameter through CREATE OR REPLACE.
drop function if exists public.banksim_simulated_transfer(uuid, text, numeric, text, uuid);

create function public.banksim_simulated_transfer(
  p_sender_id uuid,
  p_recipient_account text,
  p_amount numeric,
  p_encrypted_memo text,
  p_idempotency_key uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  recipient_id uuid;
  sender_account_number text;
  recipient_account_number text;
  sender_balance numeric(14, 2);
  recipient_balance numeric(14, 2);
  existing_reference text;
  posted_reference text;
begin
  if p_amount is null or p_amount <= 0 or p_amount > 5000 or p_amount <> round(p_amount, 2) then
    raise exception 'SIMULATED_INVALID_AMOUNT';
  end if;
  if p_idempotency_key is null then
    raise exception 'SIMULATED_INVALID_IDEMPOTENCY_KEY';
  end if;
  if p_encrypted_memo is null or length(p_encrypted_memo) > 12000 then
    raise exception 'SIMULATED_INVALID_MEMO';
  end if;

  select uuid, account_number
    into recipient_id, recipient_account_number
    from public.bank_users
    where upper(account_number) = upper(trim(p_recipient_account));
  if not found then
    raise exception 'SIMULATED_RECIPIENT_NOT_FOUND';
  end if;
  if recipient_id = p_sender_id then
    raise exception 'SIMULATED_SELF_TRANSFER_NOT_ALLOWED';
  end if;

  -- A stable lock order serializes concurrent transfers without reciprocal-transfer deadlocks.
  perform uuid
    from public.bank_users
    where uuid in (p_sender_id, recipient_id)
    order by uuid
    for update;

  select account_number, balance
    into sender_account_number, sender_balance
    from public.bank_users
    where uuid = p_sender_id;
  if not found then
    raise exception 'SIMULATED_ACCOUNT_NOT_FOUND';
  end if;

  select reference into existing_reference
    from public.banksim_simulated_transactions
    where account_owner_id = p_sender_id
      and transaction_type = 'TRANSFER_DEBIT'
      and idempotency_key = p_idempotency_key;
  if found then
    return jsonb_build_object('reference', existing_reference, 'balance', sender_balance);
  end if;

  if sender_balance < p_amount then
    raise exception 'INSUFFICIENT_SIMULATED_FUNDS';
  end if;

  update public.bank_users
    set balance = balance - p_amount
    where uuid = p_sender_id
    returning balance into sender_balance;
  update public.bank_users
    set balance = balance + p_amount
    where uuid = recipient_id
    returning account_number, balance into recipient_account_number, recipient_balance;

  posted_reference := 'SIM-' || upper(substr(encode(extensions.gen_random_bytes(8), 'hex'), 1, 12));
  insert into public.banksim_simulated_transactions (
    reference, account_owner_id, transaction_type, amount,
    counterparty_account, memo, balance_after, idempotency_key
  ) values (
    posted_reference, p_sender_id, 'TRANSFER_DEBIT', p_amount,
    recipient_account_number, p_encrypted_memo, sender_balance, p_idempotency_key
  );
  insert into public.banksim_simulated_transactions (
    reference, account_owner_id, transaction_type, amount,
    counterparty_account, memo, balance_after
  ) values (
    posted_reference, recipient_id, 'TRANSFER_CREDIT', p_amount,
    sender_account_number, 'Incoming BankSim transfer', recipient_balance
  );

  return jsonb_build_object('reference', posted_reference, 'balance', sender_balance);
end;
$$;

revoke execute on function public.banksim_simulated_deposit(uuid, numeric, uuid)
  from public, anon, authenticated;
revoke execute on function public.banksim_simulated_transfer(uuid, text, numeric, text, uuid)
  from public, anon, authenticated;
grant execute on function public.banksim_simulated_deposit(uuid, numeric, uuid)
  to service_role;
grant execute on function public.banksim_simulated_transfer(uuid, text, numeric, text, uuid)
  to service_role;
