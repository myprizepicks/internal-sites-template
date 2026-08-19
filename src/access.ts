/**
 * Cloudflare Access identity helpers and routing mode detection.
 *
 * Auth model:
 *   - ctx.access is populated automatically by the Workers runtime when
 *     Cloudflare Access authenticates a request. No manual JWT verification
 *     or environment secrets are needed.
 *   - In local development, `wrangler dev` simulates ctx.access using the
 *     `access.dev` block in wrangler.jsonc.
 *
 * Routing mode (separate from auth) is auto-detected:
 *   - workers.dev / localhost / placeholder domain → path-based routing (/sites/slug/)
 *   - Real custom domain                          → subdomain routing (slug.company.com)
 */

import type { ExecutionContext } from "hono";
import type { Env } from "./env";
import { jwtVerify, createRemoteJWKSet } from "jose";

export interface AccessIdentity {
	email: string;
	userId?: string;
}

const DEFAULT_PLACEHOLDER_DOMAIN = "internal-company.com";

// ── Routing mode detection ───────────────────────────────────────────────────

/**
 * Detect whether path-based routing should be used.
 *
 * Path-based routing is active when:
 *   - The request hostname ends with `.workers.dev`
 *   - The request hostname is `localhost` (wrangler dev)
 *   - SITE_DOMAIN is empty or still the default placeholder
 *
 * This is separate from auth — workers.dev uses path-based routing but
 * still requires Access authentication for platform and deployed-site routes.
 */
export function isTestingMode(request: Request, env: Env): boolean {
	const hostname = new URL(request.url).hostname;
	const domain = (env.SITE_DOMAIN || "").trim();

	return (
		hostname.endsWith(".workers.dev") ||
		hostname === "localhost" ||
		hostname.startsWith("127.") ||
		domain === "" ||
		domain === DEFAULT_PLACEHOLDER_DOMAIN
	);
}

// ── Public auth API ──────────────────────────────────────────────────────────

function toAccessIdentity(
	identity: CloudflareAccessIdentity | undefined,
): AccessIdentity {
	return {
		email: identity?.email ?? "unknown",
		userId: identity?.user_uuid,
	};
}

/**
 * Extract the verified identity from the execution context.
 *
 * ctx.access is populated by the Workers runtime when Cloudflare Access
 * authenticates the request. Returns null if Access did not run.
 */
export async function getAccessIdentity(
	ctx: ExecutionContext,
): Promise<AccessIdentity | null> {
	if (!ctx.access) {
		return null;
	}

	try {
		return toAccessIdentity(await ctx.access.getIdentity());
	} catch {
		return null;
	}
}

/**
 * Require a verified identity. Returns the identity or a 401 Response.
 *
 * ctx.access is defined when Cloudflare Access has authenticated the request.
 * If ctx.access is undefined, Access is not enabled on this Worker.
 */
export async function requireAccessIdentity(
	ctx: ExecutionContext, req: Request, env: Env,
): Promise<AccessIdentity | Response> {
	const accessIdentity = await getAccessIdentity(ctx);
	if (accessIdentity) {
		return accessIdentity;
	} else {
		console.log("Missing Access Identity, falling back to token verification");
	}

	const token = req.headers.get("cf-access-jwt-assertion");

	// Check if token exists
	if (!token) {
		console.log("Missing required CF Access JWT");
		return new Response("Missing required CF Access JWT", {
			status: 401,
			headers: { "Content-Type": "text/plain" },
		});
	} else {
		console.log("CF Access JWT found");
	}

	try {
		// Create JWKS from your team domain
		const JWKS = createRemoteJWKSet(
			new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`)
		);

		// Verify the JWT
		const { payload } = await jwtVerify(token, JWKS, {
			issuer: env.TEAM_DOMAIN,
			audience: env.POLICY_AUD,
		});

		// Token is valid, proceed with your application logic
		if (typeof payload.email !== "string") {
			throw new Error("Token is missing a valid email claim");
		}

		return {
			email: payload.email,
			userId:
				typeof payload.user_uuid === "string"
					? payload.user_uuid
					: undefined,
		};
	} catch (error) {
		// Token verification failed
		const message = error instanceof Error ? error.message : "Unknown error";
		return new Response(`Invalid token: ${message}`, {
			status: 403,
			headers: { "Content-Type": "text/plain" },
		});
	}
}
