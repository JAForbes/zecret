import { KnownKeyAuthority } from './server-login'

// > zecret signup --email=james@harth.io --username=jmsfbs --key-authority=github:JAForbes --ssh-key=~/.ssh/id_rsa
//
// Key verified:
//
// Click this link to receive an account confirmation email:
//
// https://zecret.dev/auth/signup/:token
//

export type SignupCommand = {
	tag: 'SignupCommand'
	value: {
		// zecret username
		username: string

		// so we can do transactional stuff
		email: string

		// so we know who you are
		known_key_authority: KnownKeyAuthority

		// so we can encrypt the response
		public_key: string
	}
}

// we don't really need a confirmation step, we can encrypt a link, CLI decrypts it with their private key
// they click the link, it creates the account when it is visited
// maybe to keep it simple, we enforce verification of email so they click the link, it sends the email
// they click the link in the email, and then the account is active

export type SignupResponseOk = {
	tag: 'SignupResponseOk'
	value: {
		// a link encrypted with their public key
		// visiting it will send an email confirmation
		// and create the account on confirmation
		account_creation_link_enc: string
		// the public key used to encrypt the link
		public_key: string
	}
}

export type SignupResponseErr = {
	tag: 'SignupResponseErr'
	value: {
		message: string
	}
}

export type SignupResponse = SignupResponseOk | SignupResponseErr

export async function SignupCommand(
	command: SignupCommand
): Promise<SignupResponse> {}
