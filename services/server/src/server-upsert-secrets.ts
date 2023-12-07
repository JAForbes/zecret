import { UpsertSecret } from "./types";

type UpsertSecretsCommand = {
	tag: "UpsertSecretsCommand";
	value: {
		secrets: UpsertSecret[];
		token: string;
	};
};
type UpsertSecretsOk = {
	tag: "UpsertSecretsOk";
	value: {};
};
type UpsertSecretsErr = {
	tag: "UpsertSecretsErr";
	value: {
		message: string;
	};
};
type UpsertSecretsResponse = UpsertSecretsOk | UpsertSecretsErr;

export default async function UpsertSecretsCommand(
	command: UpsertSecretsCommand
): Promise<UpsertSecretsResponse> {
	// can this user write to this path
	await upsertSecrets({
		secrets: command.value.secrets,
		token: command.value.token,
	});
}
