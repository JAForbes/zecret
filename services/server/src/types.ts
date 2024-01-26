import { KeyAuthority, LoginCommand } from './server-login.js'
import { WhoAmICommand } from './server-whoami.js'

export type KeyPair = {
	private_key: string
	public_key: string
}

export type DecodedToken = {
	key_authority: KeyAuthority

	public_key_hash: string

	// when the token was issued
	iat: number

	// at this point check github still lists that key
	// that's it, no need to log the user out
	exp: number
}

export type EncryptedSecretRequestObject = {
	path: string

	key: string

	enc_value: string
}

export type PutCommand = {
	tag: 'PutCommand'
	value: {
		public_key: string
		secrets: EncryptedSecretRequestObject[]
	}
}

export type InitializeStoreCommand = {
	tag: 'InitializeStoreCommand'
	value: {
		key_pair: KeyPair
		token_secret: string
		database_url: string
	}
}

export type InitializeStoreOk = {
	tag: 'InitializeStoreOk'
	value: {}
}

export type InitializeStoreErr = {
	tag: 'InitializeStoreErr'
	value: {
		message: string
	}
}

export type InitializeStoreResponse = InitializeStoreOk | InitializeStoreErr

export type RollServerKeyPairCommand = {
	tag: 'RollServerKeyPairCommand'
	value: {
		old_private_key: string
		new_private_key: string
		new_public_key: string
	}
}

export type * from './server-login.js'
export type * from './server-whoami.js'
export type * from './server-token-refresh.js'
export type * from './server-state.js'

export type Command = WhoAmICommand | LoginCommand | InitializeStoreCommand
