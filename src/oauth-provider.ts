import {
	randomBytes,
	createHash,
	createHmac,
	timingSafeEqual,
} from "node:crypto";
import type { Response } from "express";
import {
	InvalidGrantError,
	InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
	OAuthClientInformationFull,
	OAuthTokens,
	OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";

// Client IDs and tokens are HMAC-signed with OAUTH_SECRET instead of stored,
// so sign-ins survive Railway restarts (an in-memory store lost them all and
// Claude got 500s until a manual re-authorize). Only the 10-minute auth codes
// live in memory. Rotating OAUTH_SECRET revokes every client and token.
const authCodes = new Map<
	string,
	{
		clientId: string;
		redirectUri: string;
		codeChallenge: string;
		expiresAt: number;
	}
>();
const ACCESS_TTL_S = 3600 * 24 * 90; // 90 days
const REFRESH_TTL_S = 3600 * 24 * 365;

type SignedClient = { k: "client"; r: string[]; n?: string; iat: number };
type SignedToken = {
	k: "access" | "refresh";
	c: string;
	exp: number;
	j: string;
};

function generateToken(length = 32): string {
	return randomBytes(length).toString("base64url");
}

function hmac(body: string): Buffer {
	return createHmac("sha256", process.env.OAUTH_SECRET ?? "")
		.update(body)
		.digest();
}

function sign(payload: SignedClient | SignedToken): string {
	const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `${body}.${hmac(body).toString("base64url")}`;
}

function verifySigned<T extends SignedClient | SignedToken>(
	value: string,
	kind: T["k"],
): T | undefined {
	const dot = value.lastIndexOf(".");
	if (dot <= 0) return undefined;
	const body = value.slice(0, dot);
	const sig = Buffer.from(value.slice(dot + 1), "base64url");
	const expected = hmac(body);
	if (sig.length !== expected.length || !timingSafeEqual(sig, expected))
		return undefined;
	try {
		const payload = JSON.parse(Buffer.from(body, "base64url").toString()) as T;
		return payload.k === kind ? payload : undefined;
	} catch {
		return undefined;
	}
}

function issueToken(
	kind: SignedToken["k"],
	clientId: string,
	ttl: number,
): string {
	const exp = Math.floor(Date.now() / 1000) + ttl;
	return sign({ k: kind, c: clientId, exp, j: generateToken(8) });
}

function verifyPkce(verifier: string, challenge: string): boolean {
	const digest = createHash("sha256").update(verifier).digest("base64url");
	return digest === challenge;
}

function escapeHtml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

const clientsStore: OAuthRegisteredClientsStore = {
	getClient(clientId: string) {
		const c = verifySigned<SignedClient>(clientId, "client");
		if (!c) return undefined;
		return {
			client_id: clientId,
			client_id_issued_at: c.iat,
			client_name: c.n,
			redirect_uris: c.r,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: "none",
		};
	},
	registerClient(
		clientInfo: Omit<
			OAuthClientInformationFull,
			"client_id" | "client_id_issued_at"
		>,
	) {
		const now = Math.floor(Date.now() / 1000);
		const clientId = sign({
			k: "client",
			r: clientInfo.redirect_uris.map(String),
			n: clientInfo.client_name,
			iat: now,
		});
		return { ...clientInfo, client_id: clientId, client_id_issued_at: now };
	},
};

export class HevyOAuthProvider implements OAuthServerProvider {
	readonly skipLocalPkceValidation = false;

	get clientsStore(): OAuthRegisteredClientsStore {
		return clientsStore;
	}

	async authorize(
		client: OAuthClientInformationFull,
		params: AuthorizationParams,
		res: Response,
	): Promise<void> {
		const serverPassword = process.env.OAUTH_SECRET;
		if (!serverPassword) {
			res.status(500).send("Server configuration error: OAUTH_SECRET not set.");
			return;
		}

		// Render a simple HTML login form. The user enters the OAUTH_SECRET
		// env var value to prove they own this server.
		res.setHeader("Content-Type", "text/html; charset=utf-8");
		res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connect Claude to Hevy</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f0f0f; color: #e0e0e0;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; margin: 0;
    }
    .card {
      background: #1a1a1a; border: 1px solid #2a2a2a;
      border-radius: 12px; padding: 2rem; max-width: 400px; width: 90%;
    }
    h1 { font-size: 1.3rem; margin: 0 0 0.4rem; color: #fff; }
    p { color: #888; font-size: 0.875rem; margin: 0 0 1.5rem; line-height: 1.5; }
    label { display: block; font-size: 0.8rem; color: #ccc; margin-bottom: 0.35rem; }
    input[type="password"] {
      width: 100%; padding: 0.6rem 0.75rem;
      border-radius: 6px; border: 1px solid #3a3a3a;
      background: #111; color: #fff; font-size: 1rem; margin-bottom: 1rem;
    }
    button {
      width: 100%; padding: 0.7rem; border-radius: 6px; border: none;
      background: #6366f1; color: #fff; font-size: 0.95rem;
      font-weight: 600; cursor: pointer;
    }
    button:hover { background: #4f46e5; }
    .err { color: #f87171; font-size: 0.82rem; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Hevy MCP Server</h1>
    <p>Enter your server password to allow <strong>${escapeHtml(client.client_name ?? "Claude")}</strong> to access your Hevy data.</p>
    <form method="POST" action="/oauth/authorize/submit">
      <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
      <input type="hidden" name="state" value="${escapeHtml(params.state ?? "")}">
      <input type="hidden" name="scope" value="${escapeHtml((params.scopes ?? []).join(" "))}">
      <label for="password">Server Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required autofocus>
      <button type="submit">Connect</button>
    </form>
  </div>
</body>
</html>`);
	}

	async challengeForAuthorizationCode(
		_client: OAuthClientInformationFull,
		authorizationCode: string,
	): Promise<string> {
		const entry = authCodes.get(authorizationCode);
		if (!entry) throw new InvalidGrantError("Unknown authorization code");
		if (Date.now() > entry.expiresAt) {
			authCodes.delete(authorizationCode);
			throw new InvalidGrantError("Authorization code expired");
		}
		return entry.codeChallenge;
	}

	async exchangeAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
		codeVerifier?: string,
		redirectUri?: string,
	): Promise<OAuthTokens> {
		const entry = authCodes.get(authorizationCode);
		if (!entry) throw new InvalidGrantError("Invalid authorization code");
		if (Date.now() > entry.expiresAt) {
			authCodes.delete(authorizationCode);
			throw new InvalidGrantError("Authorization code expired");
		}
		if (entry.clientId !== client.client_id)
			throw new InvalidGrantError("Client ID mismatch");
		if (redirectUri && entry.redirectUri !== redirectUri)
			throw new InvalidGrantError("Redirect URI mismatch");
		if (codeVerifier && !verifyPkce(codeVerifier, entry.codeChallenge))
			throw new InvalidGrantError("PKCE verification failed");
		authCodes.delete(authorizationCode);

		return {
			access_token: issueToken("access", client.client_id, ACCESS_TTL_S),
			token_type: "Bearer",
			expires_in: ACCESS_TTL_S,
			refresh_token: issueToken("refresh", client.client_id, REFRESH_TTL_S),
			scope: "",
		};
	}

	async exchangeRefreshToken(
		client: OAuthClientInformationFull,
		refreshToken: string,
	): Promise<OAuthTokens> {
		// InvalidGrantError → 400 invalid_grant, so Claude falls back to a fresh
		// authorization instead of retrying against a 500.
		const entry = verifySigned<SignedToken>(refreshToken, "refresh");
		if (!entry) throw new InvalidGrantError("Invalid refresh token");
		if (Math.floor(Date.now() / 1000) > entry.exp)
			throw new InvalidGrantError("Refresh token expired");
		if (entry.c !== client.client_id)
			throw new InvalidGrantError("Client ID mismatch");

		return {
			access_token: issueToken("access", client.client_id, ACCESS_TTL_S),
			token_type: "Bearer",
			expires_in: ACCESS_TTL_S,
			refresh_token: refreshToken,
			scope: "",
		};
	}

	async verifyAccessToken(token: string): Promise<AuthInfo> {
		// InvalidTokenError → 401, which tells Claude to refresh or re-authorize.
		const entry = verifySigned<SignedToken>(token, "access");
		if (!entry) throw new InvalidTokenError("Invalid access token");
		if (Math.floor(Date.now() / 1000) > entry.exp)
			throw new InvalidTokenError("Access token expired");
		return {
			token,
			clientId: entry.c,
			scopes: [],
			expiresAt: entry.exp,
		};
	}

	async revokeToken(
		_client: OAuthClientInformationFull,
		_request: OAuthTokenRevocationRequest,
	): Promise<void> {
		// Signed tokens can't be revoked individually; rotate OAUTH_SECRET to
		// revoke all of them.
	}

	/**
	 * Validates the submitted password and, if correct, stores an auth code
	 * that the OAuth token endpoint will exchange for an access token.
	 */
	issueAuthorizationCode(params: {
		clientId: string;
		redirectUri: string;
		codeChallenge: string;
		password: string;
	}): { code: string } | { error: string } {
		const serverPassword = process.env.OAUTH_SECRET;
		if (!serverPassword) return { error: "Server misconfigured" };
		if (params.password !== serverPassword)
			return { error: "Incorrect password" };

		const code = generateToken(24);
		authCodes.set(code, {
			clientId: params.clientId,
			redirectUri: params.redirectUri,
			codeChallenge: params.codeChallenge,
			expiresAt: Date.now() + 10 * 60 * 1000,
		});
		return { code };
	}
}
