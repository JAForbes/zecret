import assert from "assert"
import { DecodedToken } from "./types.js"
import { parseJwt, serverDecrypt, tokenBoilerPlate } from "./util.js"
import { state } from "./server-state.js"
import { error } from "console"

type RequestSecretsCommand = {
	tag: "RequestSecretsCommand"
	value: {
		organization: string
		paths: [string]
		token: string
	}
}
type SecretResponse = {
	path: string
	organization_name: string
	key: string
	value: string
}
type RequestSecretsOk = {
	tag: "RequestSecretsOk"
	value: {
		secrets: SecretResponse[]
	}
}
type RequestSecretsErr = {
	tag: "RequestSecretsErr"
	value: {
		message: string
	}
}
type RequestSecretsResponse = RequestSecretsOk | RequestSecretsErr

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

	return sql.begin( sql => {

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
	}))
}
