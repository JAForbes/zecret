import assert from "node:assert";
import * as fs from "node:fs/promises";
import jsonwebtoken from "jsonwebtoken";

import { State } from "./types";
import {
	decryptWithBufferPrivateKey,
	decryptWithGithubPrivateKey,
	encryptWithBufferPublicKey,
	encryptWithGithubPublicKey,
} from "./util";
import { LoginCommand } from "./server-login";
import { InitializeStoreCommand } from "./server-initialize";
import { state } from "./server-state";
import { WhoAmICommand } from "./server-whoami";
import RefreshTokenCommand from "./server-token-refresh";

export default async function server(argv: any & { _: string[] }) {
	const initializeStoreRes = await InitializeStoreCommand({
		tag: "InitializeStore",
		value: {
			key_pair: {
				private_key: await fs.readFile(
					"/home/self/src/@/zecret/output/keypair/server",
					"utf-8"
				),
				public_key: await fs.readFile(
					"/home/self/src/@/zecret/output/keypair/server.pub",
					"utf-8"
				),
			},
			token_secret: "secret",
		},
	});

	const loginResponse = await LoginCommand({
		tag: "LoginCommand",
		value: {
			gh: {
				public_key: await fs.readFile("/home/self/.ssh/id_rsa.pub", "utf8"),
				username: "JAForbes",
			},
		},
	});

	assert(loginResponse.tag === "LoginResponseOk");
	assert(state.state === "active");

	const jwt = await decryptWithGithubPrivateKey(
		loginResponse.value.encrypted_token,
		await fs.readFile("/home/self/.ssh/id_rsa", "utf8")
	);

	const server_enc_jwt = await encryptWithBufferPublicKey(
		jwt,
		state.key_pairs[0].public_key
	);

	const whoAmIResponse = await WhoAmICommand({
		tag: "WhoAmI",
		value: {
			token: server_enc_jwt,
		},
	});

	const refreshResponse = await RefreshTokenCommand({
		tag: "RefreshToken",
		value: {
			token: server_enc_jwt,
		},
	});

	assert(refreshResponse.tag === "RefreshTokenOk");

	console.log(whoAmIResponse);
	console.log(server_enc_jwt, refreshResponse.value.token);
}
