import { KeyAuthority } from './server-login.js'
import { tokenBoilerPlate } from './util.js'
import R from 'ramda'

export type GroupUser = {
	tag: 'GroupUser'
	group_name: string
	user_id: string
}
export type GroupKeyAuthorityUser = {
	tag: 'GroupKeyAuthorityUser'
	group_name: string
	keyAuthority: KeyAuthority
}
export type GroupMember = GroupUser | GroupKeyAuthorityUser
export type UserGrant = {
	tag: 'UserGrant'
	user_name: string
	path: string
	grant_level: 'write' | 'read'
}
export type KeyAuthorityUserGrant = {
	tag: 'KeyAuthorityUserGrant'
	key_authority: KeyAuthority
	path: string
	grant_level: 'write' | 'read'
}
export type GroupGrant = {
	tag: 'GroupGrant'
	group_name: string
	path: string
	grant_level: 'write' | 'read'
}
export type Grant = KeyAuthorityUserGrant | UserGrant | GroupGrant
export type ManageOrganizationCommand = {
	tag: 'ManageOrganizationCommand'
	value: {
		token: string
		organization_name: string
		admins: {
			add: string[]
			remove: string[]
		}
		groups: {
			add: string[]
			remove: string[]
		}
		users: {
			add: string[]
			remove: string[]
		}
		group_members: {
			add: GroupMember[]
			remove: GroupMember[]
		}
		grants: {
			add: Grant[]
			remove: Grant[]
		}
	}
}

export type ManageOrganizationOk = {
	tag: 'ManageOrganizationOk'
	value: {}
}

export type ManageOrganizationErr = {
	tag: 'ManageOrganizationErr'
	value: {
		message: string
	}
}

export type ManageOrganizationResponse =
	| ManageOrganizationOk
	| ManageOrganizationErr

export default async function ManageOrganizationCommand(
	theirCommand: ManageOrganizationCommand
): Promise<ManageOrganizationResponse> {
	let {
		token,
		organization_name,
		admins,
		groups,
		grants,
		group_members,
		users
	} = theirCommand.value
	const [error, data] = await tokenBoilerPlate(
		(message) =>
			({
				tag: 'ManageOrganizationErr',
				value: { message }
			} as ManageOrganizationErr),
		token
	)
	if (error) {
		return error
	}
	const sql = data.state.postgres
	return sql
		.begin(async (sql) => {
			await sql`
				select 
					zecret.set_active_user(U.user_name) 
					${
						data.decoded.key_authority.tag === 'OrgKeyAuthority'
							? sql`, zecret.set_active_org(${data.decoded.key_authority.organization_name})`
							: sql``
					}
				from zecret.user U
				${
					data.decoded.key_authority.tag === 'ZecretKeyAuthority'
						? sql`where U.user_name = ${data.decoded.key_authority.user_name}`
						: data.decoded.key_authority.tag === 'KnownKeyAuthority'
						? sql`
							inner join zecret.known_key_authority_user_name KAU
							on U.user_name = KAU.user_name
							and KAU.key_authority_name = ${data.decoded.key_authority.key_authority_name}
							and KAU.key_authority_user_name = ${data.decoded.key_authority.user_name}
						`
						: data.decoded.key_authority.tag === 'OrgKeyAuthority'
						? sql`
							inner join zecret.org_key_authority_user_name OAU
							on U.user_name = OAU.user_name
							and OAU.key_authority_name = ${data.decoded.key_authority.key_authority_name}
							and OAU.key_authority_user_name = ${data.decoded.key_authority.user_name}
							and OAU.organization_name = ${data.decoded.key_authority.organization_name}
						`
						: sql`where false`
				}
			`

			// create org if it doesn't exist, if it does exist
			// check if we are the owner, if we aren't, error, if we are, continue
			const createResult = await sql`
				insert into zecret.org(organization_name)
				values (${organization_name})
				on conflict (organization_name) do nothing
			`

			await sql`
				insert into zecret.org_user(organization_name, user_name)
				values (${organization_name}, zecret.get_active_user())
				on conflict do nothing
			`

			if (createResult.count == 0) {
				const [{ is_owner }] = await sql`
					select primary_owner_id = zecret.get_active_user() as is_owner
					from zecret.org
					where organization_name = ${organization_name}
				`.catch(() => [{ is_owner: false }])

				if (!is_owner) {
					return {
						tag: 'ManageOrganizationErr',
						value: {
							message: 'Organization could not be created, it may already exist'
						}
					} as ManageOrganizationErr
				}
			}

			// next we remove any admins that are in the admins.remove section
			await sql`
				delete from zecret.org_admin OA
				where (OA.organization_name, OA.user_id) in ${sql(
					admins.remove.flatMap((user_id) =>
						true ? [sql([organization_name, user_id])] : []
					)
				)}
			`

			// now we add any admins that are in admins.add section
			// if the group already exists we ignore it
			if (admins.add.length > 0) {
				await sql`
					insert into zecret.org_admin
					${sql(
						admins.add.map((user_id) => ({
							user_id,
							organization_name: organization_name
						})),
						'organization_name',
						'user_id'
					)}
					on conflict do nothing
				`
			}

			// next we remove any groups that are in the groups.remove section
			await sql`
				delete from zecret.group G where (G.group_name, G.organization_name) in 
					${sql(groups.remove.map((group_name) => sql([group_name, organization_name])))}
				
			`
			// now we add any groups that are in groups.add section
			// if the group already exists we ignore it
			if (groups.add.length > 0) {
				await sql`
					insert into zecret.group
					${sql(
						groups.add.map((group_name) => ({
							group_name,
							organization_name: organization_name
						})),
						'organization_name',
						'group_name'
					)}
					on conflict do nothing
				`
			}

			// From here on in, within the API / CLI / UI you can add users via their github etc.
			// We allow this even before that user has signed up by recording the grant to that key authority.
			//
			// When the user signs up, we insert a key authority user record which
			// is picked up by the RLS so they will automatically get access
			// in group related queries.

			const types: Grant['tag'][] = [
				'GroupGrant',
				'KeyAuthorityUserGrant',
				'UserGrant' // UserGrant must come last, or at least after KeyAuthorityUserGrant
			]

			let filterGrants = (t: Grant['tag'], op: 'add' | 'remove') => {
				return grants[op].filter((x) => x.tag === t)
			}

			for (let [type, op] of types.flatMap(
				(t) =>
					[
						[t, 'remove'],
						[t, 'add']
					] as const
			)) {
				await (async (): Promise<true> => {
					let filtered = filterGrants(type, op)
					if (filtered.length === 0) return true

					switch (type) {
						case 'GroupGrant': {
							const mapped = filtered.flatMap((x) =>
								x.tag === 'GroupGrant'
									? [
											{
												organization_name: theirCommand.value.organization_name,
												group_name: x.group_name,
												path: x.path,
												grant_level: x.grant_level
											}
									  ]
									: []
							)
							switch (op) {
								case 'add': {
									await sql`
										insert into zecret.grant_group
										${sql(mapped)}
									`
									return true
								}
								case 'remove': {
									await sql`
										delete from zecret.grant_group
										${sql(mapped)}
									`
									return true
								}
							}
						}

						// we only store key authority grants if the user doesn't exist yet
						// if the user does exist we instead create a user grant
						// in the `types` list, UserGrant comes last, so we just push into the
						// `grants` list our UserGrants where applicable and they get picked up
						// in the next phase
						case 'KeyAuthorityUserGrant': {
							// note there is so much duplication here
							// but the schema is young, so that may change if org/zecret/known
							// key authority schemas drift, but you could almost have a single table with a nullable org name
							// and an enum column for known / org / zecret, you could also parameterize a lot of this code
							// keep the schema distinct but unify the code, I'm going to keep it sprawling and repetitive for now
							// until it settles a bit
							let kats: KeyAuthority['tag'][] = [
								'KnownKeyAuthority',
								'OrgKeyAuthority',
								'ZecretKeyAuthority'
							]
							for (let kat of kats) {
								switch (kat) {
									case 'KnownKeyAuthority': {
										const mapped = filtered.flatMap((x) =>
											x.tag === 'KeyAuthorityUserGrant' &&
											x.key_authority.tag === 'KnownKeyAuthority'
												? [
														{
															organization_name:
																theirCommand.value.organization_name,
															key_authority_user_name:
																x.key_authority.user_name,
															key_authority_name:
																x.key_authority.key_authority_name,
															grant_level: x.grant_level,
															path: x.path
														}
												  ]
												: []
										)

										// check if any users already exists
										const infoIdx = await sql<
											{
												key_authority_user_name: string
												user_name?: string
												exists: boolean
											}[]
										>`
											select 
												request.key_authority_user_name
												, K.key_authority_user_name is not null as exists
												, K.user_name as user_name
											from (
												${sql(mapped.map((x) => Object.values(x)))}
											) as request(
												, key_authority_user_name
												, key_authority_name
											)
											left join known_key_authority_user_name(
												key_authority_name, key_authority_user_name,
											) as K
										`.then((xs) =>
											xs.reduce(
												(p, n) => ({
													...p,
													[n.key_authority_user_name]: {
														exists: n.exists,
														user_name: n.user_name
													}
												}),
												{} as Record<
													string,
													{ exists: boolean; user_name?: string }
												>
											)
										)

										let [doesExist, doesNotExist] = R.partition(
											(x) => infoIdx[x.key_authority_user_name].exists,
											mapped
										)

										// for the existing users we'll handle them in the UserGrant section
										grants[op].push(
											...doesExist.map(
												(x) =>
													({
														grant_level: x.grant_level,
														path: x.path,
														user_name:
															infoIdx[x.key_authority_user_name].user_name!,
														tag: 'UserGrant'
													} as UserGrant)
											)
										)
										switch (op) {
											case 'add':
												await sql`
													insert into zecret.grant_known_key_authority_user 
													${sql(doesNotExist)}
												`
												return true
											case 'remove':
												await sql`
													delete from zecret.grant_known_key_authority_user
													where (
														organization_name
														, path
														, grant_level
														, key_authority_name
														, key_authority_user_name
													) in ${sql(
														doesNotExist,
														'organization_name',
														'path',
														'grant_level',
														'key_authority_name',
														'key_authority_user_name'
													)}
												`
												return true
										}
									}
									case 'OrgKeyAuthority': {
										const mapped = filtered.flatMap((x) =>
											x.tag === 'KeyAuthorityUserGrant' &&
											x.key_authority.tag === 'OrgKeyAuthority'
												? [
														{
															organization_name:
																theirCommand.value.organization_name,
															key_authority_user_name:
																x.key_authority.user_name,
															key_authority_name:
																x.key_authority.key_authority_name,
															grant_level: x.grant_level,
															path: x.path
														}
												  ]
												: []
										)

										// check if any users already exists
										const infoIdx = await sql<
											{
												key_authority_user_name: string
												user_name?: string
												exists: boolean
											}[]
										>`
											select 
												request.key_authority_user_name
												, K.key_authority_user_name is not null as exists
												, K.user_name as user_name
											from (
												${sql(mapped.map((x) => Object.values(x)))}
											) as request(
												, key_authority_user_name
												, key_authority_name
											)
											left join org_key_authority_user_name(
												key_authority_name, key_authority_user_name,
											) as K
										`.then((xs) =>
											xs.reduce(
												(p, n) => ({
													...p,
													[n.key_authority_user_name]: {
														exists: n.exists,
														user_name: n.user_name
													}
												}),
												{} as Record<
													string,
													{ exists: boolean; user_name?: string }
												>
											)
										)

										let [doesExist, doesNotExist] = R.partition(
											(x) => infoIdx[x.key_authority_user_name].exists,
											mapped
										)

										// for the existing users we'll handle them in the UserGrant section
										grants[op].push(
											...doesExist.map(
												(x) =>
													({
														grant_level: x.grant_level,
														path: x.path,
														user_name:
															infoIdx[x.key_authority_user_name].user_name!,
														tag: 'UserGrant'
													} as UserGrant)
											)
										)
										switch (op) {
											case 'add':
												await sql`
													insert into zecret.grant_org_key_authority_user 
													${sql(doesNotExist)}
												`
												return true
											case 'remove':
												await sql`
													delete from zecret.grant_org_key_authority_user
													where (
														organization_name
														, path
														, grant_level
														, key_authority_name
														, key_authority_user_name
													) in ${sql(
														doesNotExist,
														'organization_name',
														'path',
														'grant_level',
														'key_authority_name',
														'key_authority_user_name'
													)}
												`
												return true
										}
									}
									case 'ZecretKeyAuthority': {
										const mapped = filtered.flatMap((x) =>
											x.tag === 'KeyAuthorityUserGrant' &&
											x.key_authority.tag === 'ZecretKeyAuthority'
												? [
														{
															organization_name:
																theirCommand.value.organization_name,
															key_authority_user_name:
																x.key_authority.user_name,
															key_authority_name: 'zecret',
															grant_level: x.grant_level,
															path: x.path
														}
												  ]
												: []
										)

										// check if any users already exists
										const infoIdx = await sql<
											{
												key_authority_user_name: string
												user_name?: string
												exists: boolean
											}[]
										>`
											select 
												request.key_authority_user_name
												, K.key_authority_user_name is not null as exists
												, K.user_name as user_name
											from (
												${sql(mapped.map((x) => Object.values(x)))}
											) as request(
												, key_authority_user_name
												, key_authority_name
											)
											left join known_key_authority_user_name(
												key_authority_name, key_authority_user_name,
											) as K
										`.then((xs) =>
											xs.reduce(
												(p, n) => ({
													...p,
													[n.key_authority_user_name]: {
														exists: n.exists,
														user_name: n.user_name
													}
												}),
												{} as Record<
													string,
													{ exists: boolean; user_name?: string }
												>
											)
										)

										let [doesExist, doesNotExist] = R.partition(
											(x) => infoIdx[x.key_authority_user_name].exists,
											mapped
										)

										// for the existing users we'll handle them in the UserGrant section
										grants[op].push(
											...doesExist.map(
												(x) =>
													({
														grant_level: x.grant_level,
														path: x.path,
														user_name:
															infoIdx[x.key_authority_user_name].user_name!,
														tag: 'UserGrant'
													} as UserGrant)
											)
										)
										switch (op) {
											case 'add':
												await sql`
													insert into zecret.grant_known_key_authority_user 
													${sql(doesNotExist)}
												`
												return true
											case 'remove':
												await sql`
													delete from zecret.grant_known_key_authority_user
													where (
														organization_name
														, path
														, grant_level
														, key_authority_name
														, key_authority_user_name
													) in ${sql(
														doesNotExist,
														'organization_name',
														'path',
														'grant_level',
														'key_authority_name',
														'key_authority_user_name'
													)}
												`
												return true
										}
									}
								}
							}
						}
						case 'UserGrant': {
							const mapped = filtered.flatMap((x) =>
								x.tag === 'UserGrant'
									? [
											{
												organization_name: theirCommand.value.organization_name,
												path: x.path,
												grant_level: x.grant_level,
												user_name: x.user_name
											}
									  ]
									: []
							)
							switch (op) {
								case 'add':
									await sql`
										insert into zecret.grant_user ${sql(mapped)}
									`
									return true
								case 'remove':
									await sql`
										delete from zecret.grant_user where (
											organization_name, path, grant_level, user_name
										) in ${sql(mapped.map((x) => Object.values(x)))}
									`
									return true
							}
						}
					}
				})()
			}

			// now we move onto org membership, we'll remove
			// users first
			await sql`
				delete from zecret.org_user U
				where (U.organization_name, U.user_id) in ${sql(
					users.remove.map((user_id) => sql([organization_name, user_id]))
				)}
			`

			// and add them
			if (users.add.length > 0) {
				await sql`
					insert into zecret.org_user
					${sql(
						users.add.map((user_id) => ({
							user_id,
							organization_name: organization_name
						})),
						'organization_name',
						'user_id'
					)}
					on conflict do nothing
				`
			}

			// now we proceed to group membership, same process
			await sql`
				delete from zecret.group_user GU
				where (GU.organization_name, GU.group_name, GU.user_id) in ${sql(
					group_members.remove
						.flatMap((x) => (x.tag === 'GroupUser' ? [x] : []))
						.map((o) => sql([organization_name, o.group_name, o.user_id]))
				)}
			`

			if (group_members.add.filter((x) => x.tag === 'GroupUser').length) {
				await sql`
					insert into zecret.group_user
					${sql(
						group_members.add
							.flatMap((x) => (x.tag === 'GroupUser' ? [x] : []))
							.map((o) => ({
								...o,
								organization_name: organization_name
							})),
						'organization_name',
						'group_name',
						'user_id'
					)}
					on conflict do nothing
				`
			}
			if (group_members.add.filter((x) => x.tag === 'GroupUser').length) {
				await sql`
					insert into zecret.group_user
					${sql(
						group_members.add
							.flatMap((x) => (x.tag === 'GroupUser' ? [x] : []))
							.map((o) => ({
								...o,
								organization_name: organization_name
							})),
						'organization_name',
						'group_name',
						'user_id'
					)}
					on conflict do nothing
				`
			}

			// and grants
			// first user grants
			await sql`
				delete from zecret.grant_user G
				where (G.organization_name, G.path, G.grant_level, G.user_id) in ${sql(
					grants.remove.flatMap((o) =>
						o.tag === 'UserGrant'
							? [sql([organization_name, o.path, o.grant_level, o.user_name])]
							: []
					)
				)}
			`

			if (grants.add.filter((x) => x.tag === 'UserGrant').length) {
				await sql`
					insert into zecret.grant_user
					${sql(
						grants.add.flatMap((o) =>
							o.tag === 'UserGrant'
								? [
										{
											...o,
											organization_name: organization_name
										}
								  ]
								: []
						),
						'organization_name',
						'path',
						'grant_level',
						'user_name'
					)}
					on conflict do nothing
				`
			}

			await sql`
				delete from zecret.grant_group G
				where (G.organization_name, G.path, G.grant_level, G.group_name) in ${sql(
					grants.remove.flatMap((o) =>
						o.tag === 'GroupGrant'
							? [sql([organization_name, o.path, o.grant_level, o.group_name])]
							: []
					)
				)}
			`

			// and now group grants
			await sql`
				delete from zecret.grant_group G
				where (G.organization_name, G.path, G.grant_level, G.group_name) in ${sql(
					grants.remove.flatMap((o) =>
						o.tag === 'GroupGrant'
							? [sql([organization_name, o.path, o.grant_level, o.group_name])]
							: []
					)
				)}
			`

			if (grants.add.filter((x) => x.tag === 'GroupGrant').length) {
				await sql`
					insert into zecret.grant_group
					${sql(
						grants.add.flatMap((o) =>
							o.tag === 'GroupGrant'
								? [
										{
											...o,
											organization_name: organization_name
										}
								  ]
								: []
						),
						'organization_name',
						'path',
						'grant_level',
						'group_name'
					)}
					on conflict do nothing
				`
			}

			return {
				tag: 'ManageOrganizationOk',
				value: {}
			} as ManageOrganizationOk
		})
		.catch((err) => {
			const expectedError = err.message.includes(
				'violates row-level security policy'
			)
			expectedError || console.error(err)
			return {
				tag: 'ManageOrganizationErr',
				value: {
					message: expectedError ? 'Insufficient Permissions' : 'Unknown Error'
				}
			} as ManageOrganizationResponse
		})
}
