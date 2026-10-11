import { createClient, type User } from "@supabase/supabase-js";

let banksimIdentityVerifier: ReturnType<typeof createClient> | null = null;

function getIdentityVerifier() {
  if (banksimIdentityVerifier) return banksimIdentityVerifier;
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonymousKey = process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !supabaseAnonymousKey) {
    throw new Error("Authentication is unavailable: configure SUPABASE_URL and SUPABASE_ANON_KEY.");
  }
  banksimIdentityVerifier = createClient(supabaseUrl, supabaseAnonymousKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  return banksimIdentityVerifier;
}

export async function verifyBankSimAccessToken(accessToken: string): Promise<User> {
  const { data: verifiedIdentity, error: identityFailure } = await getIdentityVerifier().auth.getUser(
    accessToken,
  );
  if (identityFailure || !verifiedIdentity.user) {
    throw new Error("Your sign-in session is invalid or expired. Please sign in again.");
  }
  return verifiedIdentity.user;
}
