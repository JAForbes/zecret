import { state } from "./server-state";
import { DecryptedToken } from "./types";
import jsonwebtoken from "jsonwebtoken";

import randomString from "crypto-random-string";
import {
	encryptWithGithubPublicKey,
	handleFetchFailure,
	parseJwt,
	serverDecrypt,
} from "./util";
import assert from "assert";
import crypto from "crypto";

export type RefreshTokenCommand = {
	tag: "RefreshToken";
	value: {
		token: string;
	};
};
export type RefreshTokenOk = {
	tag: "RefreshTokenOk";
	value: {
		token: string;
	};
};
export type RefreshTokenErr = {
	tag: "RefreshTokenErr";
	value: {
		message: string;
	};
};
export type RefreshTokenResponse = RefreshTokenOk | RefreshTokenErr;

export default async function RefreshTokenCommand(
	command: RefreshTokenCommand
): Promise<RefreshTokenResponse> {
	let token: string | null;

	try {
		token = serverDecrypt(command.value.token);
	} catch (err) {
		return {
			tag: "RefreshTokenErr",
			value: {
				message: "Could not decrypt received token using server public key",
			},
		};
	}

	assert(token != null);

	let parsedJwt: DecryptedToken | null = null;
	try {
		parsedJwt = await parseJwt(token, { autoRefresh: false });
	} catch (e) {
		return {
			tag: "RefreshTokenErr",
			value: {
				message: e.message,
			},
		};
	}
	assert(parsedJwt != null);

	const found = await fetch(
		"https://github.com/" + parsedJwt.gh.username + ".keys"
	)
		.then(handleFetchFailure)
		.then((x) => x.text())
		.then((x) => x.trim().split("\n"))
		.then((xs) =>
			xs.find((x) => {
				const hash = crypto
					.createHash("sha256")
					.update(x.trim())
					.digest("base64");

				return hash == parsedJwt?.public_key_hash;
			})
		);

	if (found == null) {
		return {
			tag: "RefreshTokenErr",
			value: {
				message: "Previous public key hash did not match keys on users github",
			},
		};
	}

	const shared_cipher = randomString({
		length: 32,
		type: "alphanumeric",
	});

	assert(state.state !== "idle");

	const new_token = jsonwebtoken.sign(
		{
			exp: Math.floor(Date.now() / 1000 + 86400),
			iat: Math.floor(Date.now() / 1000),
			gh: {
				username: parsedJwt.gh.username,
			},
			shared_cipher,
			public_key_hash: parsedJwt.public_key_hash,
		} as DecryptedToken,
		state.token_secret
	);

	const encrypted_token = encryptWithGithubPublicKey(new_token, found);

	return {
		tag: "RefreshTokenOk",
		value: {
			token: encrypted_token,
		},
	};
}
