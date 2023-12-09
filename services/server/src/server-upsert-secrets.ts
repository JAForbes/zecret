import assert from "assert"
import { DecodedToken, UpsertSecret } from "./types.js"
import { parseJwt, serverDecrypt, tokenBoilerPlate } from "./util.js"
import { state } from "./server-state.js"

type UpsertSecretsCommand = {
	tag: "UpsertSecretsCommand"
	value: {
		secrets: UpsertSecret[]
		token: string
	}
}
type UpsertSecretsOk = {
	tag: "UpsertSecretsOk"
	value: {}
}
type UpsertSecretsErr = {
	tag: "UpsertSecretsErr"
	value: {
		message: string
	}
}
type UpsertSecretsResponse = UpsertSecretsOk | UpsertSecretsErr

export default async function UpsertSecretsCommand(
	command: UpsertSecretsCommand
): Promise<UpsertSecretsResponse> {
	assert(state.state !== "idle")

	if (command.value.secrets.length === 0) {
		return {
			tag: "UpsertSecretsErr",
			value: {
				message: "You must specify a non empty secrets array"
			}
		} as UpsertSecretsResponse
	}

	const [error, data] = await tokenBoilerPlate(
		(message) =>
			({
				tag: "UpsertSecretsErr",
				value: {
					message
				}
			} as UpsertSecretsResponse),
		command.value.token
	)
	if (error) {
		return error
	}

	const sql = data.state.postgres
	console.log("hi2")
	return sql
		.begin(async (sql) => {
			await sql`
				select zecret.set_active_user(user_id)
				from zecret.user U
				where U.github_user_id = ${data.decoded.gh.username}
			`
			const publicKeys: [{ server_public_key_id: string }] = await sql`
				select server_public_key_id
				from zecret.server_public_key
				where server_public_key_pkcs8 in ${sql(
					data.state.key_pairs.map((x) => x.public_key.toString("hex"))
				)}
			`

			const inputs = command.value.secrets.flatMap((x) =>
				publicKeys.map(({ server_public_key_id }) => ({
					...x,
					value: x.value.cipher_text,
					iv: x.value.iv,
					server_public_key_id
				}))
			)

			await sql`
				insert into zecret.secret ${sql(
					inputs,
					"organization_name",
					"path",
					"key",
					"value",
					"iv",
					"server_public_key_id"
				)}


				on conflict (organization_name, path, key, server_public_key_id)
				do update set
					value = excluded.value
					,iv = excluded.value
					,updated_at = now()
			`
		})
		.then(() => {
			return {
				tag: "UpsertSecretsOk",
				value: {}
			} as UpsertSecretsResponse
		})
		.catch((err) => {
			return {
				tag: "UpsertSecretsErr",
				value: {
					message: err.message.includes("violates row-level security policy")
						? "Insufficient Permissions"
						: "Unknown Error"
				}
			} as UpsertSecretsResponse
		})
}
