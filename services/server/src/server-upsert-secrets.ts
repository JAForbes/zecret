import assert from "assert"
import { DecodedToken, UpsertSecret } from "./types.js"
import randomString from "crypto-random-string"
import {
	decryptWithSecret,
	encryptWithBufferPublicKey,
	encryptWithSecret,
	parseJwt,
	serverDecrypt,
	tokenBoilerPlate
} from "./util.js"
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

	return sql
		.begin(async (sql) => {
			await sql`
				select zecret.set_active_user(user_id)
				from zecret.user U
				where U.github_user_id = ${data.decoded.gh.username}
			`

			// Because Asymmetric encryption is slower, and has length limits
			// we use symmetric encryption with a one time secret.
			//
			// We use this secret to encrypt the value as it has stable performance
			// and no length limits.
			//
			// We then store an encrypted version of the secret on the row.
			// We encrypt the secret 1 time per API call using PKE
			// so that we can retrieve the symmetric secret, and in turn decrypt
			// the secret value.
			//
			// This means if the database was ever exposed, without the server
			// private key, nothing could be decrypted, but we don't pay the cost
			// of unbounded asymmetric encryption/decryption.
			//
			// Note we do not use the shared secret on the caller's JWT, this is
			// only used for data in transit.  This means if a users token is leaked
			// there is no direct way to decrypt a stored value without the server's
			// assistance.
			//

			// the "one time" symmetric secret, that will be used
			// to encrypt the user's value
			const symmetric_secret = randomString({
				length: 32,
				type: "alphanumeric"
			})

			// we encrypt a copy once per server key pair
			// to allow for rolling the key pair
			const inputs = data.state.key_pairs.flatMap(
				({ server_public_key_id, public_key }) => {
					// we encrypt the "one time" secret with the server's
					// public key, so it can be restored when the secret
					// is retrieved, as long as the server still has
					// access to that private key
					const encryptedSymmetricSecret = encryptWithBufferPublicKey(
						symmetric_secret,
						public_key
					)

					return command.value.secrets.map((x) => {
						// We first decrypt the secret the user sent
						// using their JWT shared secret.
						//
						// Then we encrypt using the "one time" secret
						const { cipher_text: value, iv } = encryptWithSecret(
							decryptWithSecret(x.value, data.decoded.shared_secret),
							symmetric_secret
						)
						return {
							...x,
							value,
							iv,
							server_public_key_id,
							symmetric_secret: encryptedSymmetricSecret
						}
					})
				}
			)

			await sql`
				insert into zecret.secret ${sql(
					inputs,
					"organization_name",
					"path",
					"key",
					"value",
					"iv",
					"server_public_key_id",
					"symmetric_secret"
				)}


				on conflict (organization_name, path, key, server_public_key_id)
				do update set
					value = excluded.value
					,iv = excluded.iv
					,symmetric_secret = excluded.symmetric_secret
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
			console.error(err)
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
