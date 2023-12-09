import * as util from "./util.js"
import jsonwebtoken from "jsonwebtoken"
import crypto from "crypto"
import { DecodedToken } from "./types.js"
import { state } from "./server-state.js"
import randomString from "crypto-random-string"

export type LoginCommand = {
	tag: "LoginCommand"
	value: {
		gh: {
			username: string
			public_key: string
		}
	}
}

export type LoginResponseOk = {
	tag: "LoginResponseOk"
	value: {
		encrypted_token: string
	}
}

export type LoginResponseErr = {
	tag: "LoginResponseErr"
	value: {
		message: string
	}
}

export type LoginResponse = LoginResponseOk | LoginResponseErr

export async function LoginCommand(
	command: LoginCommand
): Promise<LoginResponse> {
	if (state.state === "idle") {
		return {
			tag: "LoginResponseErr",
			value: {
				message: "Server has not yet initialized"
			}
		}
	}

	// Credit: https://github.com/shinnn/github-username-regex
	const GITHUB_USER_REGEX = /^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i

	if (!GITHUB_USER_REGEX.test(command.value.gh.username)) {
		return {
			tag: "LoginResponseErr",
			value: {
				message: "Github user was deemed to be invalid"
			}
		}
	}
	let safe_gh_user = command.value.gh.username.toLowerCase()
	let formatted_ssh_key = command.value.gh.public_key
		.trim()
		.split(" ")
		.slice(0, 2)
		.join(" ")

	const found = await fetch("https://github.com/" + safe_gh_user + ".keys")
		.then(util.handleFetchFailure)
		.then((x) => x.text())
		.then((x) => x.trim().split("\n"))
		.then((xs) =>
			xs.find((x) => {
				return x.trim() === formatted_ssh_key
			})
		)

	if (!found) {
		return {
			tag: "LoginResponseErr",
			value: {
				message: "Public key provided was not found on github profile for user"
			}
		}
	}

	const public_key_hash = crypto
		.createHash("sha256")
		.update(formatted_ssh_key)
		.digest("base64")

	const shared_secret = randomString({
		length: 32,
		type: "alphanumeric"
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
			gh: {
				username: safe_gh_user
			},
			shared_secret,
			public_key_hash
		} as DecodedToken,
		state.token_secret
	)

	// they can send the token back for all other
	// calls, and we will know it is someone
	// who had a private key associated with that github
	// account
	const encrypted_token = util.encryptWithGithubPublicKey(
		token,
		command.value.gh.public_key
	)

	const sql = state.postgres

	{
		const [err] = await sql`
			insert into zecret.user(github_user_id) values (${safe_gh_user})
			on conflict do nothing
		`.then(
			() => [null],
			(err) => [err, null]
		)

		if (err) {
			console.error(err)
			return {
				tag: "LoginResponseErr",
				value: {
					message: `Could not insert user into database`
				}
			}
		}
	}

	return {
		tag: "LoginResponseOk",
		value: {
			encrypted_token
		}
	}
}
