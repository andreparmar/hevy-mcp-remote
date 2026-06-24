import { randomBytes, createHash } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
	OAuthClientInformationFull,
	OAuthTokens,
	OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";

// In-memory stores — single-process. Railway restarts are fine since
// claude.ai will re-authenticate automatically using the refresh token flow.
const clients = new Map<string, OAuthClientInformationFull>();
const authCodes = new Map<
	string,
	{
		clientId: string;
		redirectUri: string;
		codeChallenge: string;
		expiresAt: number;
	}
>();
const accessTokens = new Map<
	string,
	{ clientId: string; scopes: string[]; expiresAt: number }
>();
const refreshTokens = new Map<
	string,
	{ clientId: string; scopes: string[]; expiresAt: number }
>();

function generateToken(length = 32): string {
	return randomBytes(length).toString("base64url");
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
		return clients.get(clientId);
	},
	registerClient(
		clientInfo: Omit<
			OAuthClientInformationFull,
			"client_id" | "client_id_issued_at"
		>,
	) {
		const clientId = generateToken(16);
		const now = Math.floor(Date.now() / 1000);
		const full: OAuthClientInformationFull = {
			...clientInfo,
			client_id: clientId,
			client_id_issued_at: now,
		};
		clients.set(clientId, full);
		return full;
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
		if (!entry) throw new Error("Unknown authorization code");
		if (Date.now() > entry.expiresAt) {
			authCodes.delete(authorizationCode);
			throw new Error("Authorization code expired");
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
		if (!entry) throw new Error("Invalid authorization code");
		if (Date.now() > entry.expiresAt) {
			authCodes.delete(authorizationCode);
			throw new Error("Authorization code expired");
		}
		if (entry.clientId !== client.client_id)
			throw new Error("Client ID mismatch");
		if (redirectUri && entry.redirectUri !== redirectUri)
			throw new Error("Redirect URI mismatch");
		if (codeVerifier && !verifyPkce(codeVerifier, entry.codeChallenge))
			throw new Error("PKCE verification failed");
		authCodes.delete(authorizationCode);

		const accessToken = generateToken();
		const refreshToken = generateToken();
		const now = Math.floor(Date.now() / 1000);
		const expiresIn = 3600 * 24 * 90; // 90 days

		accessTokens.set(accessToken, {
			clientId: client.client_id,
			scopes: [],
			expiresAt: now + expiresIn,
		});
		refreshTokens.set(refreshToken, {
			clientId: client.client_id,
			scopes: [],
			expiresAt: now + 3600 * 24 * 365,
		});

		return {
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: expiresIn,
			refresh_token: refreshToken,
			scope: "",
		};
	}

	async exchangeRefreshToken(
		client: OAuthClientInformationFull,
		refreshToken: string,
	): Promise<OAuthTokens> {
		const entry = refreshTokens.get(refreshToken);
		if (!entry) throw new Error("Invalid refresh token");
		const now = Math.floor(Date.now() / 1000);
		if (now > entry.expiresAt) {
			refreshTokens.delete(refreshToken);
			throw new Error("Refresh token expired");
		}
		if (entry.clientId !== client.client_id)
			throw new Error("Client ID mismatch");

		const accessToken = generateToken();
		const expiresIn = 3600 * 24 * 90;
		accessTokens.set(accessToken, {
			clientId: client.client_id,
			scopes: entry.scopes,
			expiresAt: now + expiresIn,
		});

		return {
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: expiresIn,
			refresh_token: refreshToken,
			scope: entry.scopes.join(" "),
		};
	}

	async verifyAccessToken(token: string): Promise<AuthInfo> {
		const entry = accessTokens.get(token);
		if (!entry) throw new Error("Invalid access token");
		const now = Math.floor(Date.now() / 1000);
		if (now > entry.expiresAt) {
			accessTokens.delete(token);
			throw new Error("Access token expired");
		}
		return {
			token,
			clientId: entry.clientId,
			scopes: entry.scopes,
			expiresAt: entry.expiresAt,
		};
	}

	async revokeToken(
		_client: OAuthClientInformationFull,
		request: OAuthTokenRevocationRequest,
	): Promise<void> {
		accessTokens.delete(request.token);
		refreshTokens.delete(request.token);
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
