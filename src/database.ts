import { GrantLevel } from "./server-grant";
import { DecodedToken } from "./types";

export type GrantStoreItem = {
	group?: string;
	user?: string;
	path: string;
	level: GrantLevel;
};

type OwnerStore = {
	github: string;
};
type SecretStore = {
	key: string;
	enc_value: string;
	path: string;
	server_public_key: string;
};

type Tables = {
	owners: OwnerStore[];
	secrets: SecretStore[];
};
const tables: Tables = {
	owners: [],
	secrets: [],
};
export async function upsertOwners(owners: string[]): Promise<void> {
	// only supported proof right now
	const ghOwners = owners
		.filter((x) => x.startsWith("gh:"))
		.map((x) => x.split("gh:")[1]);
	const storedGhOwners = new Set(tables.owners.map((x) => x.github));

	for (let owner of ghOwners) {
		if (!storedGhOwners.has(owner)) {
			tables.owners.push({
				github: owner,
			});
		}
	}
}
export async function upsertSecrets(
	secrets: { key: string; value: string; path: string },
	decodedToken: DecodedToken
): Promise<void> {}

export async function getGrants(query: {
	github: { username: string };
	level: GrantLevel;
}): Promise<GrantStoreItem[]> {
	return [];
}
