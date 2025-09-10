# OIDC Playground (Go + Clerk)

Minimal Go web app demonstrating OAuth 2.0 + OIDC login with Clerk as the identity provider. It uses the Authorization Code + PKCE flow and fetches the authenticated user's profile via Clerk's `/oauth/userinfo` endpoint.

References: [Clerk OAuth/OIDC docs](https://clerk.com/docs/oauth/single-sign-on#option-2-let-users-authenticate-into-third-party-applications-using-clerk-as-an-identity-provider-id-p)

## Prerequisites

- Go 1.21+ (tested with 1.25)
- A Clerk instance with an OAuth application configured

Collect from Clerk Dashboard:

- `CLERK_FRONTEND_API_URL` (e.g. `https://verb-noun-00.clerk.accounts.dev` or `https://clerk.<YOUR_APP_DOMAIN>.com`)
- OAuth app `Client ID`
- Add redirect URL: `http://localhost:3000/callback`

## Configure

Create `.env` at repo root:

```
CLERK_FRONTEND_API_URL=YOUR_FRONTEND_API_URL
CLERK_OAUTH_CLIENT_ID=YOUR_CLIENT_ID
OAUTH_REDIRECT_URI=http://localhost:3000/callback
OAUTH_SCOPE=openid profile email
COOKIE_SECURE=false
```

## Run

```
go run .
```

Visit `http://localhost:3000` then click `/login`. After authenticating with Clerk, you'll be redirected to `/hello`, which returns a JSON payload including your Clerk `/oauth/userinfo` response.

## Notes

- This demo stores tokens in HTTP-only cookies for simplicity. For production, store tokens server-side, set `Secure` cookies, and consider validating the ID token using your instance JWKS and checking claims.
- The app only calls `/oauth/userinfo` with the access token, which aligns with Clerk's docs for obtaining profile information.
