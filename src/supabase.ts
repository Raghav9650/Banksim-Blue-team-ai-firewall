import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const banksimSupabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim();
const banksimSupabaseAnonymousKey = import.meta.env.VITE_SUPABASE_ANON_KEY?.trim();

export const supabaseConfigurationReady = Boolean(
  banksimSupabaseUrl && banksimSupabaseAnonymousKey,
);

export const supabaseClient: SupabaseClient | null = supabaseConfigurationReady
  ? createClient(banksimSupabaseUrl!, banksimSupabaseAnonymousKey!, {
      auth: {
        autoRefreshToken: true,
        detectSessionInUrl: true,
        persistSession: true,
        storage: window.localStorage,
      },
    })
  : null;
