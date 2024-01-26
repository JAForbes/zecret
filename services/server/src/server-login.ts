import * as util from './util.js'
import jsonwebtoken from 'jsonwebtoken'
import crypto from 'crypto'
import { DecodedToken } from './types.js'
import { state } from './server-state.js'
import randomString from 'crypto-random-string'
import mustache from 'mustache'

export type KnownKeyAuthority = {
	tag: 'KnownKeyAuthority'
	key_authority_name: string
	user_name: string
}
export type OrgKeyAuthority = {
	tag: 'OrgKeyAuthority'
	key_authority_name: string
	organization_name: string
	user_name: string
}
export type ZecretKeyAuthority = {
	tag: 'ZecretKeyAuthority'
	user_name: string
}

export type KeyAuthority =
	| KnownKeyAuthority
	| OrgKeyAuthority
	| ZecretKeyAuthority

// zecret login harth/gh:jaforbes ~/.ssh/id_rsa
// { public_key: ..., key_authority: { tag: 'KnownKeyAuthority', key_authority_name: 'github', user_name: 'jaforbes' } }
//
// zecret cli associates the domain + key authority + returned token with the key pair from then on
//
// a custom authority would have to pre-registered on the server and would work like this:
//
// zecret login harth/custom:jaforbes ~/.ssh/id_rsa
// { public_key, ...
// , key_authority:
//		{ tag: 'OrgKeyAuthority'
//		, organization_name: 'harth'
//		, key_authority_name: 'github'
//		, user_name: 'jaforbes'
//		}
// }
//
// where `custom` is the name of the custom key authority and `harth` is the name of the org
// `jaforbes` is the username on the custom key server

export type LoginCommand = {
	tag: 'LoginCommand'
	value: {
		public_key: string
		key_authority: KeyAuthority
	}
}

export type LoginResponseOk = {
	tag: 'LoginResponseOk'
	value: {
		token: string
		shared_secret_enc: string
	}
}

export type LoginResponseErrSuggestionSignup = {
	tag: 'LoginResponseErrSuggestionSignup'
}
export type LoginResponseErrSuggestionLink = {
	tag: 'LoginResponseErrSuggestionLink'
}

export type LoginResponseErrSuggestion =
	| LoginResponseErrSuggestionSignup
	| LoginResponseErrSuggestionLink

export type LoginResponseErr = {
	tag: 'LoginResponseErr'
	value: {
		message: string
		suggestions: LoginResponseErrSuggestion[]
	}
}

export type LoginResponse = LoginResponseOk | LoginResponseErr

// Credit: https://github.com/shinnn/github-username-regex
const GITHUB_USER_REGEX = /^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i

export async function LoginCommand(
	command: LoginCommand
): Promise<LoginResponse> {
	if (state.state === 'idle') {
		return {
			tag: 'LoginResponseErr',
			value: {
				message: 'Server has not yet initialized',
				suggestions: []
			}
		}
	}

	// clone so we can replace properties as we validate them
	command = JSON.parse(JSON.stringify(command))

	type RegexpCheck = {
		get: (x: KeyAuthority) => [string] | []
		set: (x: KeyAuthority, value: string) => void
		display: string
	}
	for (let check of <RegexpCheck[]>[
		{
			get: (x) => (x.tag === 'OrgKeyAuthority' ? [x.organization_name] : []),
			set: (x, v) => {
				if (x.tag === 'OrgKeyAuthority') {
					x.organization_name = v
				}
			},
			display: 'Organization name'
		},
		{
			get: (x) => [x.user_name],
			set: (x, v) => (x.user_name = v),
			display: 'User name'
		},
		{
			get: (x) =>
				x.tag === 'ZecretKeyAuthority' ? ['zecret'] : [x.key_authority_name],
			set: (x, v) => {
				if (x.tag !== 'ZecretKeyAuthority') {
					x.key_authority_name = v
				}
			},
			display: 'Key authority name'
		}
	]) {
		let checked = check.get(command.value.key_authority)
		if (checked.length === 0) {
			continue
		}
		let [found] = checked
		inspect: {
			if (typeof found != 'string') {
				break inspect
			}

			found = found.trim()

			if (found.length == 0) {
				break inspect
			}

			if (!GITHUB_USER_REGEX.test(found)) {
				break inspect
			}

			check.set(command.value.key_authority, found.toLowerCase())
			continue
		}

		return {
			tag: 'LoginResponseErr',
			value: {
				message: `${check.display} was deemed to be invalid, it must match: https://github.com/shinnn/github-username-regex`,
				suggestions: []
			}
		}
	}

	const organization_name =
		command.value.key_authority.tag === 'OrgKeyAuthority'
			? command.value.key_authority.organization_name
			: null
	const sql = state.postgres

	let keyServerUrl: URL
	{
		let origin: string | null = null
		let url_template: string | null = null

		switch (command.value.key_authority.tag) {
			case 'KnownKeyAuthority': {
				void ([{ origin = null, url_template = null } = {}] = await sql`
					select origin, url_template 
					from zecret.known_key_authority
					-- rls handles filtering out unused known key authorities?
					where (key_authority_name) = (${command.value.key_authority.key_authority_name})
				`)
				break
			}
			case 'OrgKeyAuthority': {
				void ([{ origin = null, url_template = null } = {}] = await sql`
					select origin, url_template 
					from zecret.org_key_authority

					-- rls handles filtering out unused known key authorities?
					where (organization_name, key_authority_name) = (${organization_name}, ${command.value.key_authority.key_authority_name})
				`)
				break
			}
			case 'ZecretKeyAuthority': {
				void ([{ origin = null, url_template = null } = {}] = await sql`
					select ${state.config.BASE_URL} as origin, url_template 
					from zecret.known_key_authority
					-- rls handles filtering out unused known key authorities?
					where (key_authority_name) = ('zecret')
				`)
				break
			}
		}

		if (origin == null || url_template == null) {
			return {
				tag: 'LoginResponseErr',
				value: {
					message:
						'Could not obtain key authority, it may be incorrect or disabled',
					suggestions: []
				}
			}
		}

		try {
			const url_path_resolved = mustache.render(
				url_template,
				{
					user_name: encodeURIComponent(command.value.key_authority.user_name),
					organization_name: organization_name
						? encodeURIComponent(organization_name)
						: null
				},
				{},
				{
					// otherwise it treats the template as HTML instead of a URL
					escape(value) {
						return value
					}
				}
			)

			keyServerUrl = new URL(origin)
			keyServerUrl.pathname = url_path_resolved
		} catch (_) {
			return {
				tag: 'LoginResponseErr',
				value: {
					message:
						'Could not construct url from key authority, it may be misconfigured',
					suggestions: []
				}
			}
		}
	}

	let formatted_ssh_key = command.value.public_key
		.trim()
		.split(' ')
		.slice(0, 2)
		.join(' ')

	// todo-james retry
	const found = await fetch(keyServerUrl)
		.then(util.handleFetchFailure)
		.then((x) => x.text())
		.then((x) => x.trim().split('\n'))
		.then((xs) =>
			xs.find((x) => {
				return x.trim() === formatted_ssh_key
			})
		)

	if (!found) {
		return {
			tag: 'LoginResponseErr',
			value: {
				message: 'Public key provided was not found on key authority for user',
				suggestions: []
			}
		}
	}

	// first we need to check if a key authority for this username exists in zecret yet
	// if it does we grant access
	// if not, we error, but we return a suggestion to create an account
	// the CLI can then prompt them to sign up via the CLI, they just need to pick a username as we can get their email from the github/gitlab API
	// for a known key authority, for a custom authority we need an email verification step so for now we just don't allow that for now

	const [user_name] = await sql`
		select user_name
		from zecret.known_key_authority_user_name
		where ${
			command.value.key_authority.tag === 'KnownKeyAuthority' &&
			sql`
				(key_authority_name, key_authority_user_name) = (${command.value.key_authority.key_authority_name}, ${command.value.key_authority.user_name})
			`
		}
		union all
		select user_name
		from zecret.org_key_authority_user_name
		where ${
			command.value.key_authority.tag === 'OrgKeyAuthority' &&
			sql`
			(organization_name, key_authority_name, key_authority_user_name) = (${organization_name}, ${command.value.key_authority.key_authority_name}, ${command.value.key_authority.user_name})
			`
		}
		union all
		select user_name
		from zecret.known_key_authority_user_name
		where ${
			command.value.key_authority.tag !== 'ZecretKeyAuthority' &&
			sql`
				(key_authority_name, key_authority_user_name) = ('zecret', ${command.value.key_authority.user_name})
			`
		}
	`

	const public_key_hash = crypto
		.createHash('sha256')
		.update(formatted_ssh_key)
		.digest('base64')

	const shared_secret = randomString({
		length: 32,
		type: 'alphanumeric'
	})

	// if they can decrypt the encrypted token
	// they'll have a jwt that proves they are
	// the github user
	//
	// if they can't decrypt it, they'll never
	// get the jwt
	const token = jsonwebtoken.sign(
		{
			exp: Math.floor(Date.now() / 1000 + 86400),
			iat: Math.floor(Date.now() / 1000),
			key_authority: command.value.key_authority,
			public_key_hash
		} as DecodedToken,
		state.token_secret
	)

	const shared_secret_enc = util.encryptWithGithubPublicKey(
		shared_secret,
		command.value.public_key
	)

	if (!user_name) {
		return {
			tag: 'LoginResponseErr',
			value: {
				message: `No user exists with that key authority`,
				suggestions: [
					{ tag: 'LoginResponseErrSuggestionSignup' },
					{ tag: 'LoginResponseErrSuggestionLink' }
				]
			}
		}
	}

	return {
		tag: 'LoginResponseOk',
		value: {
			token,
			shared_secret_enc
		}
	}
}
