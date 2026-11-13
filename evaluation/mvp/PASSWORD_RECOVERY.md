# Password recovery

The sign-in page links to `/reset-password`. The request form sends recovery mail
through Supabase only for an allowed email address, with a generic success message
to avoid exposing the account list. No invitation or account is created.

For local development, configure Supabase Authentication > URL Configuration:

- Site URL: `http://127.0.0.1:5173`
- Redirect URLs: `http://127.0.0.1:5173/reset-password`

Set `AUTH_RECOVERY_REDIRECT_URL` to that same reset URL. For hosting, use the actual
HTTPS origin, enable secure cookies and add the exact HTTPS reset URL in Supabase.
Recovery redirects must belong to `AUTH_ALLOWED_ORIGINS`; client-supplied redirect
targets are not accepted.

The page handles implicit recovery links and expired-link errors. It removes the
fragment from browser history immediately and retains the access token only in
memory. Reloading requires a fresh link. The backend verifies the token with
Supabase and applies the normal confirmed-email allowlist before updating that
user's password. Passwords require at least 12 characters and a matching confirmation.
Provider tokens and passwords are not stored in local/session storage or logged.
Successful updates clear local session cookies and return to ordinary sign-in.

Use only the newest recovery email; expired links cannot be repaired. Users enter
and submit their own new password. The real email-to-reset flow still requires
user verification; automated tests mock only the provider HTTP boundary.

The offline demo feature and its alternate login have been removed. Existing local
demo database files are preserved and ignored by Git, with no running demo mode.
