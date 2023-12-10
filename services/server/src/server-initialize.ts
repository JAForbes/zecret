import sshpk from "sshpk"
import postgres from "postgres"
import crypto from "crypto"

import {
	InitializeStoreCommand,
	InitializeStoreResponse,
	State
} from "./types.js"
import { state, replaceState } from "./server-state.js"

export async function InitializeStoreCommand(
	command: InitializeStoreCommand
): Promise<InitializeStoreResponse> {
	if (state.state !== "idle") {
		return {
			tag: "InitializeStoreErr",
			value: {
				message: "Store is already initialized"
			}
		}
	}

	const required = [
		command.value.key_pair.private_key,
		command.value.key_pair.public_key,
		command.value.token_secret
	]
	if (!required.every((x) => x)) {
		return {
			tag: "InitializeStoreErr",
			value: {
				message: "Missing required values"
			}
		}
	}

	const sql = await postgres(command.value.database_url)
	const public_key = sshpk
		.parseKey(command.value.key_pair.public_key, "ssh")
		.toBuffer("pkcs8")
	const private_key = sshpk
		.parsePrivateKey(command.value.key_pair.private_key, "ssh")
		.toBuffer("pkcs8")

	const [err, data] = await sql`
		with effect as (
			insert into zecret.server_public_key(
				server_public_key_id, server_public_key_pkcs8
			)
			values (${crypto
				.createHash("sha256")
				.update(public_key.toString("hex"))
				.digest("hex")},${public_key.toString("hex")})
			on conflict (server_public_key_pkcs8) do nothing
			returning server_public_key_id
		)
		, backup as (
			select server_public_key_id
			from zecret.server_public_key
			where server_public_key_pkcs8 = ${public_key.toString("hex")}
		)
		select server_public_key_id
		from effect
		union all
		select server_public_key_id
		from backup
	`
		.then(([data]) => [null, data as { server_public_key_id: string }] as const)
		.catch((err) => [err as Error, null] as const)

	if (err) {
		return {
			tag: "InitializeStoreErr",
			value: {
				message: err.message
			}
		}
	}

	let newState: State = {
		state: "active",
		key_pairs: [
			{
				public_key,
				private_key,
				server_public_key_id: data.server_public_key_id
			}
		],
		postgres: sql,
		token_secret: command.value.token_secret
	}

	replaceState(newState)

	return {
		tag: "InitializeStoreOk",
		value: {}
	}
}
