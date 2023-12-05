import sshpk from "sshpk";

import { state, replaceState } from "./server-state";
import {
	InitializeStoreCommand,
	InitializeStoreResponse,
	State,
} from "./types";

export async function InitializeStoreCommand(
	command: InitializeStoreCommand
): Promise<InitializeStoreResponse> {
	if (state.state !== "idle") {
		return {
			tag: "InitializeStoreErr",
			value: {
				message: "Store is already initialized",
			},
		};
	}

	const required = [
		command.value.key_pair.private_key,
		command.value.key_pair.public_key,
		command.value.token_secret,
	];
	if (!required.every((x) => x)) {
		return {
			tag: "InitializeStoreErr",
			value: {
				message: "Missing required values",
			},
		};
	}

	let newState: State = {
		state: "active",
		key_pairs: [
			{
				public_key: sshpk
					.parseKey(command.value.key_pair.public_key, "ssh")
					.toBuffer("pkcs8"),
				private_key: sshpk
					.parsePrivateKey(command.value.key_pair.private_key, "ssh")
					.toBuffer("pkcs8"),
			},
		],
		token_secret: command.value.token_secret,
	};

	replaceState(newState);

	return {
		tag: "InitializeStoreOk",
		value: {},
	};
}
