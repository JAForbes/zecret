import jsonwebtoken, { TokenExpiredError } from "jsonwebtoken";
import assert from "node:assert";
import { state } from "./server-state";
import { DecryptedToken } from "./types";
import { decryptWithBufferPrivateKey, parseJwt, serverDecrypt } from "./util";
import { LoginCommand } from "./server-login";
import RefreshTokenCommand from "./server-token-refresh";

export type WhoAmICommand = {
	tag: "WhoAmI";
	value: {
		token: string;
	};
};

export type WhoAmIOk = {
	tag: "WhoAmIOk";
	value: {
		gh: {
			username: string;
		};
		token: string;
	};
};

export type WhoAmIErr = {
	tag: "WhoAmIErr";
	value: {
		message: string;
	};
};

export type WhoAmIResponse = WhoAmIOk | WhoAmIErr;

export async function WhoAmICommand(
	command: WhoAmICommand
): Promise<WhoAmIResponse> {
	if (state.state === "idle") {
		return {
			tag: "WhoAmIErr",
			value: {
				message: "Server has not yet initialized",
			},
		};
	}

	let token: string | null = null;
	try {
		token = serverDecrypt(command.value.token);
	} catch (err) {
		return {
			tag: "WhoAmIErr",
			value: {
				message: "Token could not be decrypted with server public key",
			},
		};
	}

	assert(token != null);

	let parsedJwt: DecryptedToken | null = null;
	try {
		parsedJwt = await parseJwt(token, { autoRefresh: true });
	} catch (e) {
		return {
			tag: "WhoAmIErr",
			value: {
				message: e.message,
			},
		};
	}
	assert(parsedJwt != null);

	return {
		tag: "WhoAmIOk",
		value: {
			gh: {
				username: parsedJwt.gh.username,
			},
			token: command.value.token,
		},
	};
}
