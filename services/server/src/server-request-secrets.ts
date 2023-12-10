import assert from "assert"
import { DecodedToken, EncryptedWithSecret } from "./types.js"
import {
	decryptWithBufferPrivateKey,
	decryptWithSecret,
	encryptWithSecret,
	tokenBoilerPlate
} from "./util.js"
import { state } from "./server-state.js"
import { error } from "console"

export type RequestSecretsCommand = {
	tag: "RequestSecretsCommand"
	value: {
		organization_name: string
		paths: [string]
		token: string
	}
}
export type SecretResponse = {
	path: string
	organization_name: string
	key: string
	value: EncryptedWithSecret
}
export type RequestSecretsOk = {
	tag: "RequestSecretsOk"
	value: {
		secrets: SecretResponse[]
	}
}
export type RequestSecretsErr = {
	tag: "RequestSecretsErr"
	value: {
		message: string
	}
}
export type RequestSecretsResponse = RequestSecretsOk | RequestSecretsErr

export default async function (
	command: RequestSecretsCommand
): Promise<RequestSecretsResponse> {
	const [err, data] = await tokenBoilerPlate(
		(message) =>
			({
				tag: "RequestSecretsErr",
				value: { message }
			} as RequestSecretsErr),
		command.value.token
	)
	if (err) {
		return err
	}

	const sql = data.state.postgres

	const [secretsErr, secretsData] = await sql
		.begin(async (sql) => {
			await sql`
				select 
					zecret.set_active_user(user_id) 
				from zecret.user 
				where github_user_id = ${data.decoded.gh.username}
			`
			const request = await sql<
				{
					path: string
					key: string
					value: string
					iv: string
					symmetric_secret: string
					server_public_key_id: string
				}[]
			>`
				select 
					distinct on (S.path, S.key) 
					S.path, S.key, S.value, S.iv, S.symmetric_secret, S.server_public_key_id

				from unnest(${command.value.paths}::text[]) J(path)
				cross join zecret.secret S
				where S.path like (J.path || '%')
				and organization_name = ${command.value.organization_name}
				and server_public_key_id in ${sql(
					data.state.key_pairs.map((x) => x.server_public_key_id)
				)}
				;
			`

			return request
		})
		.then((xs) => {
			return [null, xs] as const
		})
		.catch((err) => {
			return [
				{
					tag: "RequestSecretsErr",
					value: {
						message: err.message.includes("violates row-level security policy")
							? "Insufficient Permissions"
							: "Unknown Error"
					}
				} as RequestSecretsResponse,
				null
			] as const
		})

	if (secretsErr) {
		return secretsErr
	}

	const decryptedSymmetricSecret = new Map<string, string>()
	const responseData = secretsData.map((x) => {
		if (!decryptedSymmetricSecret.has(x.symmetric_secret)) {
			decryptedSymmetricSecret.set(
				x.symmetric_secret,
				decryptWithBufferPrivateKey(
					x.symmetric_secret,
					data.state.key_pairs.find(
						(y) => y.server_public_key_id === x.server_public_key_id
					)!.private_key
				)
			)
		}
		const symmetric_secret = decryptedSymmetricSecret.get(x.symmetric_secret)!

		// decrypt so we can re-encrypt for transit with a different secret
		const decryptedValue = decryptWithSecret(
			{
				iv: x.iv,
				cipher_text: x.value
			},
			symmetric_secret
		)

		// encrypt for transit
		const encrypted = encryptWithSecret(
			decryptedValue,
			data.decoded.shared_secret
		)

		return {
			key: x.key,
			organization_name: command.value.organization_name,
			path: x.path,
			value: encrypted
		} as SecretResponse
	})

	return {
		tag: "RequestSecretsOk",
		value: {
			secrets: responseData
		}
	}
}
