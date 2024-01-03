import assert from 'assert'
import randomString from 'crypto-random-string'
import {
	decryptWithSecret,
	encryptWithBufferPublicKey,
	encryptWithSecret,
	tokenBoilerPlate
} from './util.js'
import { state } from './server-state.js'

export type EncryptedWithSecret = {
	iv: string
	cipher_text: string
}

export type AddSecretPayload = {
	organization_name: string
	path: string
	key: string
	value: EncryptedWithSecret
}

export type RemoveSecretPayload = {
	organization_name: string
	path: string
	key: string
}

type ManageSecretsCommand = {
	tag: 'ManageSecretsCommand'
	value: {
		add: AddSecretPayload[]
		remove: RemoveSecretPayload[]
		token: string
	}
}
type ManageSecretsOk = {
	tag: 'ManageSecretsOk'
	value: {}
}
type ManageSecretsErr = {
	tag: 'ManageSecretsErr'
	value: {
		message: string
	}
}
type ManageSecretsResponse = ManageSecretsOk | ManageSecretsErr

export default async function ManageSecretsCommand(
	command: ManageSecretsCommand
): Promise<ManageSecretsResponse> {
	assert(state.state !== 'idle')

	if (command.value.add.length + command.value.remove.length === 0) {
		return {
			tag: 'ManageSecretsErr',
			value: {
				message:
					'You must specify at least one non empty secrets array for { add, remove }'
			}
		} as ManageSecretsResponse
	}

	const [error, data] = await tokenBoilerPlate(
		(message) =>
			({
				tag: 'ManageSecretsErr',
				value: {
					message
				}
			} as ManageSecretsResponse),
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
				type: 'alphanumeric'
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

					return command.value.add.map((x) => {
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

			if (command.value.add.length) {
				await sql`
					insert into zecret.secret ${sql(
						inputs,
						'organization_name',
						'path',
						'key',
						'value',
						'iv',
						'server_public_key_id',
						'symmetric_secret'
					)}
	
	
					on conflict (organization_name, path, key, server_public_key_id)
					do update set
						value = excluded.value
						,iv = excluded.iv
						,symmetric_secret = excluded.symmetric_secret
						,server_public_key_id = excluded.server_public_key_id
						,updated_at = now()
				`
			}

			const deletedResponse = await sql`
				delete from zecret.secret S
				where (S.organization_name, S.path, S.key) in ${sql(
					command.value.remove.map((remove) =>
						sql([remove.organization_name, remove.path, remove.key])
					)
				)}
			`
		})
		.then(() => {
			return {
				tag: 'ManageSecretsOk',
				value: {}
			} as ManageSecretsResponse
		})
		.catch((err) => {
			const expectedErr = err.message.includes(
				'violates row-level security policy'
			)
			expectedErr || console.error(err)
			return {
				tag: 'ManageSecretsErr',
				value: {
					message: expectedErr ? 'Insufficient Permissions' : 'Unknown Error'
				}
			} as ManageSecretsResponse
		})
}
