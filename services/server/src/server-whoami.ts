import jsonwebtoken, { TokenExpiredError } from 'jsonwebtoken'
import assert from 'node:assert'
import { state } from './server-state.js'
import { DecodedToken } from './types.js'
import {
	decryptWithBufferPrivateKey,
	parseJwt,
	serverDecrypt,
	tokenBoilerPlate
} from './util.js'
import { LoginCommand } from './server-login.js'
import RefreshTokenCommand from './server-token-refresh.js'

export type WhoAmICommand = {
	tag: 'WhoAmICommand'
	value: {
		token: string
	}
}

export type WhoAmIOk = {
	tag: 'WhoAmIOk'
	value: {
		gh: {
			username: string
		}
	}
}

export type WhoAmIErr = {
	tag: 'WhoAmIErr'
	value: {
		message: string
	}
}

export type WhoAmIResponse = WhoAmIOk | WhoAmIErr

export async function WhoAmICommand(
	command: WhoAmICommand
): Promise<WhoAmIResponse> {
	const [error, data] = await tokenBoilerPlate(
		(message) => ({ tag: 'WhoAmIErr', value: { message } } as WhoAmIErr),
		command.value.token
	)
	if (error) {
		return error
	}
	return {
		tag: 'WhoAmIOk',
		value: {
			gh: {
				username: data.decoded.gh.username
			}
		}
	}
}
