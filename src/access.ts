/**
 * Cloudflare Access identity helpers and routing mode detection.
 *
 * Auth model:
 *   - ctx.access is populated when the Workers runtime receives Access context
 *     directly (e.g. local dev via access.dev in wrangler.jsonc).
 *   - Workers with Static Assets run behind an internal router that does not
 *     pass ctx.access. In production, identity is resolved by verifying the
 *     Cf-Access-Jwt-Assertion header (or CF_Authorization cookie) and calling
 *     /cdn-cgi/access/get-identity on the team domain.
 *
 * Routing mode (separate from auth) is auto-detected:
 *   - workers.dev / localhost / placeholder domain → path-based routing (/sites/slug/)
 *   - Real custom domain                          → subdomain routing (slug.company.com)
 */

import type { ExecutionContext } from "hono";
import type { JWTPayload } from "jose";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Env } from "./env";

export interface AccessIdentity {
	email: string;
	userId?: string;
}

const DEFAULT_PLACEHOLDER_DOMAIN = "internal-company.com";

const UNAUTHENTICATED_MESSAGE =
	"Setup required: Enable Cloudflare Access\n\nProtect this Worker behind Access so only company employees can sign in.";

const jwksByTeamDomain = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Clears cached JWKS clients. For unit tests only. */
export function resetAccessAuthCacheForTests(): void {
	jwksByTeamDomain.clear();
}

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

// ── Token extraction and verification ────────────────────────────────────────

function getCachedJwks(teamDomain: string) {
	let jwks = jwksByTeamDomain.get(teamDomain);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
		jwksByTeamDomain.set(teamDomain, jwks);
	}
	return jwks;
}

function extractAccessToken(req: Request): string | null {
	const headerToken = req.headers.get("cf-access-jwt-assertion");
	if (headerToken) {
		return headerToken;
	}

	const cookieHeader = req.headers.get("Cookie");
	if (!cookieHeader) {
		return null;
	}

	for (const part of cookieHeader.split(";")) {
		const trimmed = part.trim();
		const separator = trimmed.indexOf("=");
		if (separator === -1) {
			continue;
		}

		const name = trimmed.slice(0, separator);
		if (name === "CF_Authorization") {
			return decodeURIComponent(trimmed.slice(separator + 1));
		}
	}

	return null;
}

function validateAccessEnv(env: Env): Response | null {
	if (!env.TEAM_DOMAIN?.trim()) {
		return new Response("Missing TEAM_DOMAIN configuration", {
			status: 500,
			headers: { "Content-Type": "text/plain" },
		});
	}

	if (!env.POLICY_AUD?.trim()) {
		return new Response("Missing POLICY_AUD configuration", {
			status: 500,
			headers: { "Content-Type": "text/plain" },
		});
	}

	return null;
}

async function verifyAccessJwt(
	token: string,
	env: Env,
): Promise<JWTPayload> {
	const { payload } = await jwtVerify(token, getCachedJwks(env.TEAM_DOMAIN), {
		issuer: env.TEAM_DOMAIN,
		audience: env.POLICY_AUD,
	});
	return payload;
}

async function fetchAccessIdentity(
	token: string,
	env: Env,
): Promise<CloudflareAccessIdentity | null> {
	try {
		const response = await fetch(
			`${env.TEAM_DOMAIN}/cdn-cgi/access/get-identity`,
			{
				headers: { Cookie: `CF_Authorization=${token}` },
			},
		);

		if (!response.ok) {
			return null;
		}

		return (await response.json()) as CloudflareAccessIdentity;
	} catch {
		return null;
	}
}

// ── Identity mapping ─────────────────────────────────────────────────────────

function toAccessIdentity(
	identity: CloudflareAccessIdentity | undefined,
): AccessIdentity {
	return {
		email: identity?.email ?? "unknown",
		userId: identity?.user_uuid,
	};
}

function identityFromJwtPayload(payload: JWTPayload): AccessIdentity {
	if (typeof payload.email !== "string") {
		throw new Error("Token is missing a valid email claim");
	}

	return {
		email: payload.email,
		userId: typeof payload.sub === "string" ? payload.sub : undefined,
	};
}

// ── Public auth API ──────────────────────────────────────────────────────────

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
 * Require a verified identity. Returns the identity or an error Response.
 *
 * Resolution order:
 *   1. ctx.access.getIdentity() when the runtime provides Access context
 *   2. Verify Cf-Access-Jwt-Assertion / CF_Authorization, then hydrate via
 *      /cdn-cgi/access/get-identity (fallback to JWT claims on API failure)
 */
export async function requireAccessIdentity(
	ctx: ExecutionContext,
	req: Request,
	env: Env,
): Promise<AccessIdentity | Response> {
	const contextIdentity = await getAccessIdentity(ctx);
	if (contextIdentity) {
		return contextIdentity;
	}

	const configError = validateAccessEnv(env);
	if (configError) {
		return configError;
	}

	const token = extractAccessToken(req);
	if (!token) {
		return new Response(UNAUTHENTICATED_MESSAGE, {
			status: 401,
			headers: { "Content-Type": "text/plain" },
		});
	}

	let payload: JWTPayload;
	try {
		payload = await verifyAccessJwt(token, env);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Unknown error";
		return new Response(`Invalid token: ${message}`, {
			status: 403,
			headers: { "Content-Type": "text/plain" },
		});
	}

	const hydratedIdentity = await fetchAccessIdentity(token, env);
	if (hydratedIdentity) {
		return toAccessIdentity(hydratedIdentity);
	}

	try {
		return identityFromJwtPayload(payload);
	} catch (error) {
		const message = error instanceof Error ? error.message : "Unknown error";
		return new Response(`Invalid token: ${message}`, {
			status: 403,
			headers: { "Content-Type": "text/plain" },
		});
	}
}
