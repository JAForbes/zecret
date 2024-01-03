import sshpk from 'sshpk'
import crypto from 'node:crypto'
import assert from 'assert'
import jsonwebtoken from 'jsonwebtoken'
import { ActiveState, state } from './server-state.js'
import { DecodedToken } from './types.js'
import RefreshTokenCommand from './server-token-refresh.js'
import { EncryptedWithSecret } from './server-manage-secrets.js'

export const handleFetchFailure = async (x: Response): Promise<Response> => {
	if (!x.ok) {
		let err = new Error(
			x.status + ': ' + (await x.text().catch(() => 'Unknown exception'))
		)
		;(err as any).status = x.status
		throw err
	}
	return x
}

export function encryptWithBufferPublicKey(
	message: string,
	publicKeyX509: Buffer
): string {
	const cipherText = crypto.publicEncrypt(
		publicKeyX509.toString('utf8') as string,
		message as any
	)

	return cipherText.toString('base64')
}

export function decryptWithBufferPrivateKey(
	cipher_text_base64: string,
	privateKeyPkcs8: Buffer
): string {
	const decryptedBuffer = crypto.privateDecrypt(
		privateKeyPkcs8.toString('utf8'),
		Buffer.from(cipher_text_base64, 'base64')
	)

	return decryptedBuffer.toString('utf8')
}

export function encryptWithGithubPublicKey(
	message: string,
	ghPublicKey: string
): string {
	const publicKey = sshpk.parseKey(ghPublicKey, 'ssh')
	const publicKeyX509 = publicKey.toBuffer('pkcs8')

	const cipherText = crypto.publicEncrypt(
		publicKeyX509.toString('utf8') as string,
		message as any
	)

	return cipherText.toString('base64')
}

export function decryptWithGithubPrivateKey(
	cipher_text_base64: string,
	ghPrivateKey: string
): string {
	const privateKey = sshpk.parsePrivateKey(ghPrivateKey, 'ssh')
	const privateKeyPkcs8 = privateKey.toBuffer('pkcs8')
	const decryptedBuffer = crypto.privateDecrypt(
		privateKeyPkcs8.toString('utf8'),
		Buffer.from(cipher_text_base64, 'base64')
	)

	return decryptedBuffer.toString('utf8')
}

export function serverDecrypt(message: string) {
	assert(state.state !== 'idle')

	let decryptError = null
	let decryptedMessage: string | null = null
	for (let kp of state.key_pairs) {
		try {
			decryptedMessage = decryptWithBufferPrivateKey(message, kp.private_key)
			decryptError = null
		} catch (err) {
			decryptError = err
			continue
		}
	}
	if (decryptError) {
		throw decryptError
	}
	assert(decryptedMessage != null)
	return decryptedMessage
}

export async function parseJwt(
	token: string,
	options: { autoRefresh: boolean }
) {
	let parsedJwt: DecodedToken | null = null
	assert(state.state !== 'idle')

	parseToken: {
		let message = 'Token could not be verified'
		try {
			parsedJwt = jsonwebtoken.verify(token, state.token_secret) as DecodedToken
			break parseToken
		} catch (err) {
			if (
				options.autoRefresh &&
				err instanceof jsonwebtoken.TokenExpiredError
			) {
				try {
					const res = await RefreshTokenCommand({
						tag: 'RefreshTokenCommand',
						value: {
							token
						}
					})
					if (res.tag === 'RefreshTokenErr') {
						message = 'Token expired and could not be refreshed'
					} else {
						token = res.value.token
						try {
							parsedJwt = jsonwebtoken.verify(
								token,
								state.token_secret
							) as DecodedToken
							break parseToken
						} catch (err2) {
							err = err2
						}
					}
				} catch (err2) {
					err = err2
				}
			}
			throw new Error(message)
		}
	}

	assert(parsedJwt != null)

	return parsedJwt
}

export function encryptWithSecret(
	message: string,
	secret: string
): EncryptedWithSecret {
	let iv = crypto.randomBytes(16)
	let key = Buffer.from(secret)
	let cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
	let encrypted = cipher.update(message, 'utf-8', 'hex') + cipher.final('hex')
	return {
		iv: iv.toString('hex'),
		cipher_text: encrypted
	}
}
export function decryptWithSecret(
	message: { iv: string; cipher_text: string },
	secret: string
): string {
	let iv = Buffer.from(message.iv, 'hex')
	let key = Buffer.from(secret)
	const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

	let decrypted =
		decipher.update(message.cipher_text, 'hex', 'utf-8') +
		decipher.final('utf8')

	return decrypted
}

export async function tokenBoilerPlate<ErrorType>(
	onError: (message: string) => ErrorType,
	unsafeToken: string
): Promise<
	[ErrorType, null] | [null, { decoded: DecodedToken; state: ActiveState }]
> {
	if (state.state === 'idle') {
		return [onError('Server has not yet initialized'), null]
	}

	let token: string | null = null
	try {
		token = serverDecrypt(unsafeToken)
	} catch (err) {
		return [
			onError('Token could not be decrypted with server public key'),
			null
		]
	}

	assert(token != null)

	let parsedJwt: DecodedToken | null = null
	try {
		parsedJwt = await parseJwt(token, { autoRefresh: true })
	} catch (e) {
		return [onError(e instanceof Error ? e.message : 'Unknown Failure'), null]
	}
	assert(parsedJwt != null)
	return [null, { decoded: parsedJwt, state }]
}
