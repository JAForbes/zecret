import assert from "node:assert"
import * as fs from "node:fs/promises"
import jsonwebtoken from "jsonwebtoken"

import { State } from "./types.js"
import {
	decryptWithBufferPrivateKey,
	decryptWithGithubPrivateKey,
	decryptWithSecret,
	encryptWithBufferPublicKey,
	encryptWithGithubPublicKey,
	encryptWithSecret,
	parseJwt
} from "./util.js"
import { LoginCommand } from "./server-login.js"
import { InitializeStoreCommand } from "./server-initialize.js"
import { state } from "./server-state.js"
import { WhoAmICommand } from "./server-whoami.js"
import RefreshTokenCommand from "./server-token-refresh.js"
import UpsertSecretsCommand from "./server-upsert-secrets.js"
import CreateOrgCommand from "./server-create-org.js"
import RequestSecretsCommand from "./server-request-secrets.js"

export default async function server(argv: any & { _: string[] }) {
	const initializeStoreRes = await InitializeStoreCommand({
		tag: "InitializeStoreCommand",
		value: {
			key_pair: {
				private_key: await fs.readFile(
					"/home/self/src/@/zecret/output/keypair/server",
					"utf-8"
				),
				public_key: await fs.readFile(
					"/home/self/src/@/zecret/output/keypair/server.pub",
					"utf-8"
				)
			},
			database_url: "postgres://zecret_api:password@postgres:5432/postgres",
			token_secret: "secret"
		}
	})

	const loginResponse = await LoginCommand({
		tag: "LoginCommand",
		value: {
			gh: {
				public_key: await fs.readFile("/home/self/.ssh/id_rsa.pub", "utf8"),
				username: "JAForbes"
			}
		}
	})

	assert(loginResponse.tag === "LoginResponseOk")
	assert(state.state === "active")

	const jwt = await decryptWithGithubPrivateKey(
		loginResponse.value.encrypted_token,
		await fs.readFile("/home/self/.ssh/id_rsa", "utf8")
	)

	let server_enc_jwt = await encryptWithBufferPublicKey(
		jwt,
		state.key_pairs[0].public_key
	)

	const whoAmIResponse = await WhoAmICommand({
		tag: "WhoAmICommand",
		value: {
			token: server_enc_jwt
		}
	})

	const refreshResponse = await RefreshTokenCommand({
		tag: "RefreshTokenCommand",
		value: {
			token: server_enc_jwt
		}
	})

	assert(refreshResponse.tag === "RefreshTokenOk")

	console.log(whoAmIResponse)

	const encodedJwt = decryptWithGithubPrivateKey(
		refreshResponse.value.token,
		await fs.readFile("/home/self/.ssh/id_rsa", "utf8")
	)
	const parsedJwt = await parseJwt(encodedJwt, { autoRefresh: false })

	server_enc_jwt = await encryptWithBufferPublicKey(
		encodedJwt,
		state.key_pairs[0].public_key
	)
	const createOrgResponse = await CreateOrgCommand({
		tag: "CreateOrgCommand",
		value: {
			organization_name: "harth",
			token: server_enc_jwt
		}
	})

	const upsertSecretsResponse = await UpsertSecretsCommand({
		tag: "UpsertSecretsCommand",
		value: {
			token: server_enc_jwt,
			secrets: [
				{
					organization_name: "harth",
					key: "DATABASE_URL",
					value: encryptWithSecret(
						"postgres://api:password@odin.db:5432/database",
						parsedJwt.shared_secret
					),
					path: "/odin/api"
				},
				{
					organization_name: "harth",
					key: "DATABASE_URL",
					value: encryptWithSecret(
						"postgres://sql:password@odin.db:5432/database",
						parsedJwt.shared_secret
					),
					path: "/odin/sql"
				},
				{
					organization_name: "harth",
					key: "DATABASE_URL",
					value: encryptWithSecret(
						"postgres://auth:password@odin.db:5432/database",
						parsedJwt.shared_secret
					),
					path: "/odin/auth"
				},
				{
					organization_name: "harth",
					key: "DATABASE_URL",
					value: encryptWithSecret(
						"postgres://api:password@dropoff.db:5432/database",
						parsedJwt.shared_secret
					),
					path: "/dropoff/api"
				}
			]
		}
	})

	assert.equal(upsertSecretsResponse.tag, "UpsertSecretsOk")

	const cliRequestSecretsResponse = await RequestSecretsCommand({
		tag: "RequestSecretsCommand",
		value: {
			organization_name: "harth",
			paths: ["/odin"],
			token: server_enc_jwt
		}
	})

	assert(cliRequestSecretsResponse.tag === "RequestSecretsOk")
	assert.notEqual(cliRequestSecretsResponse.value.secrets.length, 0)

	assert.equal(
		"postgres://api:password@odin.db:5432/database",
		decryptWithSecret(
			cliRequestSecretsResponse.value.secrets.find(
				(x) => x.path === "/odin/api" && x.key == "DATABASE_URL"
			)!.value,
			parsedJwt.shared_secret
		)
	)
}
