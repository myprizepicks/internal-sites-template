import {
	exportJWK,
	generateKeyPair,
	SignJWT,
	type CryptoKey,
	type JWTPayload,
} from "jose";
import { fetchMock } from "./fetch-mock";

let keyPair: { publicKey: CryptoKey; privateKey: CryptoKey } | null = null;

async function getTestKeyPair() {
	if (!keyPair) {
		keyPair = await generateKeyPair("ES256");
	}
	return keyPair;
}

export async function mockAccessJwks(teamDomain: string): Promise<void> {
	const { publicKey } = await getTestKeyPair();
	const jwk = await exportJWK(publicKey);

	fetchMock
		.get(teamDomain)
		.intercept({ path: "/cdn-cgi/access/certs", method: "GET" })
		.reply(
			200,
			{ keys: [{ ...jwk, kid: "test-kid", alg: "ES256", use: "sig" }] },
			{ headers: { "content-type": "application/json" } },
		);
}

export async function createAccessJwt(
	claims: JWTPayload,
	env: { TEAM_DOMAIN: string; POLICY_AUD: string },
): Promise<string> {
	const { privateKey } = await getTestKeyPair();

	return new SignJWT(claims)
		.setProtectedHeader({ alg: "ES256", kid: "test-kid" })
		.setIssuer(env.TEAM_DOMAIN)
		.setAudience(env.POLICY_AUD)
		.setIssuedAt()
		.setExpirationTime("2h")
		.sign(privateKey);
}

export function mockAccessGetIdentity(
	teamDomain: string,
	identity: Record<string, unknown>,
): void {
	fetchMock
		.get(teamDomain)
		.intercept({ path: "/cdn-cgi/access/get-identity", method: "GET" })
		.reply(200, identity, {
			headers: { "content-type": "application/json" },
		});
}

export function mockAccessGetIdentityFailure(teamDomain: string): void {
	fetchMock
		.get(teamDomain)
		.intercept({ path: "/cdn-cgi/access/get-identity", method: "GET" })
		.reply(401, { error: "unauthorized" }, {
			headers: { "content-type": "application/json" },
		});
}
