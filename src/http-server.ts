/**
 * HTTP entry point for hevy-mcp-remote.
 *
 * Exposes the full MCP tool set over Streamable HTTP (the 2025-03-26 spec)
 * with OAuth 2.0 Dynamic Client Registration so claude.ai's "Add custom
 * connector" flow can authenticate against this server without ever seeing
 * the Hevy API key.
 *
 * Required env vars:
 *   HEVY_API_KEY   – your Hevy API key (never sent to clients)
 *   OAUTH_SECRET   – password shown on the authorization page
 *   PORT           – (optional) defaults to 3000
 *   PUBLIC_URL     – full public URL, e.g. https://hevy-mcp.up.railway.app
 */

import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { registerBodyMeasurementTools } from "./tools/body-measurements.js";
import { registerFolderTools } from "./tools/folders.js";
import { registerRoutineTools } from "./tools/routines.js";
import { registerTemplateTools } from "./tools/templates.js";
import { registerUserTools } from "./tools/user.js";
import { registerWebhookTools } from "./tools/webhooks.js";
import { registerWorkoutTools } from "./tools/workouts.js";
import { assertApiKey, parseConfig } from "./utils/config.js";
import { createClient } from "./utils/hevyClient.js";
import { HevyOAuthProvider } from "./oauth-provider.js";

const HEVY_API_BASEURL = "https://api.hevyapp.com";

function buildMcpServer(apiKey: string): McpServer {
	const server = new McpServer({ name: "hevy-mcp", version: "1.0.0" });
	const hevyClient = createClient(apiKey, HEVY_API_BASEURL);
	registerWorkoutTools(server, hevyClient);
	registerRoutineTools(server, hevyClient);
	registerTemplateTools(server, hevyClient);
	registerFolderTools(server, hevyClient);
	registerBodyMeasurementTools(server, hevyClient);
	registerUserTools(server, hevyClient);
	registerWebhookTools(server, hevyClient);
	return server;
}

export async function runHttpServer() {
	const cfg = parseConfig(process.argv.slice(2), process.env);
	assertApiKey(cfg.apiKey);
	const apiKey = cfg.apiKey as string;

	if (!process.env.OAUTH_SECRET) {
		console.error("OAUTH_SECRET env var is required for HTTP mode.");
		process.exit(1);
	}

	const port = Number(process.env.PORT ?? 3000);
	const publicUrl = process.env.PUBLIC_URL?.replace(/\/$/, "");
	if (!publicUrl) {
		console.error(
			"PUBLIC_URL env var is required for HTTP mode (e.g. https://your-app.up.railway.app).",
		);
		process.exit(1);
	}

	const issuerUrl = new URL(publicUrl);
	const oauthProvider = new HevyOAuthProvider();

	// Root Express app — handles OAuth endpoints + /mcp
	const app = createMcpExpressApp({ host: "0.0.0.0" });
	app.use(express.urlencoded({ extended: false }));
	app.use(express.json());

	// Health check MUST be registered before mcpAuthRouter so it isn't
	// intercepted by the auth middleware stack.
	app.get("/health", (_req, res) => {
		res.json({
			status: "ok",
			server: "hevy-mcp",
			transport: "streamable-http",
		});
	});

	// OAuth 2.0 endpoints: /.well-known/*, /register, /authorize, /token, /revoke
	app.use(
		mcpAuthRouter({
			provider: oauthProvider,
			issuerUrl,
			resourceName: "Hevy MCP Server",
		}),
	);

	// Form submission handler for the authorization page password check.
	// The mcpAuthRouter renders the authorize page via oauthProvider.authorize(),
	// which outputs a form POSTing here.
	app.post("/oauth/authorize/submit", (req, res) => {
		const { client_id, redirect_uri, code_challenge, state, password } =
			req.body as Record<string, string>;

		const result = oauthProvider.issueAuthorizationCode({
			clientId: client_id,
			redirectUri: redirect_uri,
			codeChallenge: code_challenge,
			password,
		});

		if ("error" in result) {
			// Re-render the form with an error message
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connect Claude to Hevy</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f0f0f; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 2rem; max-width: 400px; width: 90%; }
    h1 { font-size: 1.3rem; margin: 0 0 0.4rem; color: #fff; }
    p { color: #888; font-size: 0.875rem; margin: 0 0 1rem; line-height: 1.5; }
    label { display: block; font-size: 0.8rem; color: #ccc; margin-bottom: 0.35rem; }
    input[type="password"] { width: 100%; padding: 0.6rem 0.75rem; border-radius: 6px; border: 1px solid #3a3a3a; background: #111; color: #fff; font-size: 1rem; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.7rem; border-radius: 6px; border: none; background: #6366f1; color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #4f46e5; }
    .err { color: #f87171; font-size: 0.82rem; margin-bottom: 0.75rem; background: #2a1a1a; padding: 0.5rem 0.75rem; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Hevy MCP Server</h1>
    <div class="err">Incorrect password. Please try again.</div>
    <form method="POST" action="/oauth/authorize/submit">
      <input type="hidden" name="client_id" value="${escHtml(client_id ?? "")}">
      <input type="hidden" name="redirect_uri" value="${escHtml(redirect_uri ?? "")}">
      <input type="hidden" name="code_challenge" value="${escHtml(code_challenge ?? "")}">
      <input type="hidden" name="state" value="${escHtml(state ?? "")}">
      <label for="password">Server Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required autofocus>
      <button type="submit">Connect</button>
    </form>
  </div>
</body>
</html>`);
			return;
		}

		const redirectUrl = new URL(redirect_uri);
		redirectUrl.searchParams.set("code", result.code);
		if (state) redirectUrl.searchParams.set("state", state);
		res.redirect(redirectUrl.toString());
	});

	// Bearer-auth middleware for /mcp
	const bearerAuth = requireBearerAuth({
		verifier: oauthProvider,
		resourceMetadataUrl: `${publicUrl}/.well-known/oauth-protected-resource`,
	});

	// Each POST to /mcp gets its own stateless transport + fresh MCP server.
	// Stateless is correct for claude.ai — it sends every request cold.
	app.post("/mcp", bearerAuth, async (req, res) => {
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: undefined, // stateless
		});
		const mcpServer = buildMcpServer(apiKey);
		await mcpServer.connect(transport);
		await transport.handleRequest(req, res, req.body);
		await mcpServer.close();
	});

	// GET /mcp for SSE-streaming (optional, for clients that open a persistent stream)
	app.get("/mcp", bearerAuth, async (req, res) => {
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => randomUUID(),
		});
		const mcpServer = buildMcpServer(apiKey);
		await mcpServer.connect(transport);
		await transport.handleRequest(req, res);
	});

	app.delete("/mcp", bearerAuth, async (req, res) => {
		res
			.status(405)
			.json({ error: "Session termination not supported in stateless mode" });
	});

	app.listen(port, "0.0.0.0", () => {
		console.log(`hevy-mcp HTTP server listening on port ${port}`);
		console.log(`Public URL: ${publicUrl}`);
		console.log(`MCP endpoint: ${publicUrl}/mcp`);
		console.log(
			`OAuth discovery: ${publicUrl}/.well-known/oauth-authorization-server`,
		);
	});
}

// Prevent a single bad request from killing the process
process.on("uncaughtException", (err) => {
	console.error("Uncaught exception:", err);
});
process.on("unhandledRejection", (reason) => {
	console.error("Unhandled rejection:", reason);
});

// Self-invoke when used as an entry point (mirrors cli.ts pattern)
void runHttpServer().catch((error: unknown) => {
	console.error("Fatal error:", error);
	process.exit(1);
});

function escHtml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}
