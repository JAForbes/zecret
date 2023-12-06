import assert from "assert";
import { decryptWithBufferPrivateKey, parseJwt, serverDecrypt } from "./util";
import { state } from "./server-state";
import { DecodedToken } from "./types";

export type GrantLevel = "read" | "write" | "grant";
export type GrantCommandItem =
	| {
			tag: "GrantGroup";
			value: {
				group: string;
				path: string;
				level: GrantLevel;
			};
	  }
	| {
			tag: "GrantUser";
			value: {
				user: {
					github: {
						username: string;
					};
				};
				path: string;
				level: GrantLevel;
			};
	  };

export type GrantCommand = {
	tag: "GrantCommand";
	value: {
		token: string;
		grants: GrantCommandItem[];
	};
};
export type GrantCommandOk = {
	tag: "GrantCommandOk";
};
export type GrantCommandErr = {
	tag: "GrantCommandErr";
	value: {
		message: string;
	};
};
export type GrantCommandResponse = GrantCommandOk | GrantCommandErr;
export default async function GrantCommand(
	command: GrantCommand
): Promise<GrantCommandResponse> {
	assert(state.state !== "idle");

	let parsedJwt: DecodedToken | null = null;
	try {
		let jwt = serverDecrypt(command.value.token);
		parsedJwt = await parseJwt(jwt, { autoRefresh: true });
	} catch (e) {
		return {
			tag: "GrantCommandErr",
			value: {
				// todo-james, get more specific with the error cause here
				message: "Could not decrypt/decode provided JWT",
			},
		};
	}

	let tokenGrants = await getGrants({
		github: {
			username: parsedJwt.gh.username,
		},
		level: "grant",
	});
}
