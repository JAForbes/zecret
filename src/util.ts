import sshpk from "sshpk";
import crypto from "node:crypto";
import assert from "assert";
import jsonwebtoken, { TokenExpiredError } from "jsonwebtoken";
import { state } from "./server-state";
import { DecryptedToken } from "./types";
import RefreshTokenCommand from "./server-token-refresh";

export const handleFetchFailure = async (x: Response): Promise<Response> => {
	if (!x.ok) {
		let err = new Error(
			x.status + ": " + (await x.text().catch(() => "Unknown exception"))
		);
		(err as any).status = x.status;
		throw err;
	}
	return x;
};

export function encryptWithBufferPublicKey(
	message: string,
	publicKeyX509: Buffer
): string {
	const cipherText = crypto.publicEncrypt(
		publicKeyX509.toString("utf8") as string,
		message as any
	);

	return cipherText.toString("base64");
}

export function decryptWithBufferPrivateKey(
	cipher_text_base64: string,
	privateKeyPkcs8: Buffer
): string {
	const decryptedBuffer = crypto.privateDecrypt(
		privateKeyPkcs8.toString("utf8"),
		Buffer.from(cipher_text_base64, "base64")
	);

	return decryptedBuffer.toString("utf8");
}

export function encryptWithGithubPublicKey(
	message: string,
	ghPublicKey: string
): string {
	const publicKey = sshpk.parseKey(ghPublicKey, "ssh");
	const publicKeyX509 = publicKey.toBuffer("pkcs8");

	const cipherText = crypto.publicEncrypt(
		publicKeyX509.toString("utf8") as string,
		message as any
	);

	return cipherText.toString("base64");
}

export function decryptWithGithubPrivateKey(
	cipher_text_base64: string,
	ghPrivateKey: string
): string {
	const privateKey = sshpk.parsePrivateKey(ghPrivateKey, "ssh");
	const privateKeyPkcs8 = privateKey.toBuffer("pkcs8");
	const decryptedBuffer = crypto.privateDecrypt(
		privateKeyPkcs8.toString("utf8"),
		Buffer.from(cipher_text_base64, "base64")
	);

	return decryptedBuffer.toString("utf8");
}

export function serverDecrypt(message: string) {
	assert(state.state !== "idle");

	let decryptError = null;
	let decryptedMessage: string | null = null;
	for (let kp of state.key_pairs) {
		try {
			decryptedMessage = decryptWithBufferPrivateKey(message, kp.private_key);
			decryptError = null;
		} catch (err) {
			decryptError = err;
			continue;
		}
	}
	if (decryptError) {
		throw decryptError;
	}
	assert(decryptedMessage != null);
	return decryptedMessage;
}

export async function parseJwt(
	token: string,
	options: { autoRefresh: boolean }
) {
	let parsedJwt: DecryptedToken | null = null;
	assert(state.state !== "idle");

	parseToken: {
		let message = "Token could not be verified";
		try {
			parsedJwt = jsonwebtoken.verify(token, state.token_secret);
			break parseToken;
		} catch (err) {
			if (options.autoRefresh && err instanceof TokenExpiredError) {
				try {
					const res = await RefreshTokenCommand({
						tag: "RefreshToken",
						value: {
							token,
						},
					});
					if (res.tag === "RefreshTokenErr") {
						message = "Token expired and could not be refreshed";
					} else {
						token = res.value.token;
						try {
							parsedJwt = jsonwebtoken.verify(token, state.token_secret);
							break parseToken;
						} catch (err2) {
							err = err2;
						}
					}
				} catch (err2) {
					err = err2;
				}
			}
			throw new Error(message);
		}
	}

	assert(parsedJwt != null);

	return parsedJwt;
}
