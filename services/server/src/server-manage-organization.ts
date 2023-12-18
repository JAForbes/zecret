import { tokenBoilerPlate } from './util.js'

export type GroupUser = {
	tag: 'GroupUser'
	group_name: string
	user_id: string
}
export type GroupGithubUser = {
	tag: 'GroupGithubUser'
	group_name: string
	github_user_id: string
}
export type GroupMember = GroupUser | GroupGithubUser
export type UserGrant = {
	tag: 'UserGrant'
	user_id: string
	path: string
	grant_level: 'write' | 'read'
}
export type GithubUserGrant = {
	tag: 'GithubUserGrant'
	github_user_id: string
	path: string
	grant_level: 'write' | 'read'
}
export type GroupGrant = {
	tag: 'GroupGrant'
	group_name: string
	path: string
	grant_level: 'write' | 'read'
}
export type Grant = GithubUserGrant | UserGrant | GroupGrant
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
				select zecret.set_active_user(user_id)
				from zecret.user U
				where U.github_user_id = ${data.decoded.gh.username}
			`

			// create org if it doesn't exist, if it does exist
			// check if we are the owner, if we aren't, error, if we are, continue
			const createResult = await sql`
				insert into zecret.org(organization_name)
				values (${organization_name})
				on conflict (organization_name) do nothing
			`

			await sql`
				insert into zecret.org_user(organization_name, user_id)
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

			// From here on in, within the API / CLI / UI you can add users via their github
			// and probably other trusted platforms.  But in the schema we don't want an explosion
			// of complexity, so we just create an internal user for every mention of a github user
			// So let's do that right now

			{
				const grantUserIds = [...grants.add, ...grants.remove]
					.flatMap((x) => (x.tag === 'GithubUserGrant' ? [x] : []))
					.map((x) => x.github_user_id)

				const groupUserIds = [...group_members.add, ...group_members.remove]
					.flatMap((x) => (x.tag === 'GroupGithubUser' ? [x] : []))
					.map((x) => x.github_user_id)

				const uniq = [...new Set([...grantUserIds, ...groupUserIds])]

				console.log('uniq', uniq)
				const usersRes = await sql`
					insert into zecret.user(github_user_id)
					values ${sql(uniq)}
					on conflict do nothing
				`

				console.log()
				console.log('users.count', usersRes.count)

				const orgUsersRes = await sql`
					insert into zecret.org_user(organization_name, user_id)
					
					select O.organization_name, U.user_id
					from zecret.user U
					cross join zecret.org O
					where O.organization_name = ${organization_name}
					and U.github_user_id in ${sql(uniq)}
					on conflict do nothing
				`
				console.log('org_users.count', orgUsersRes.count)

				const userIdx = await sql`
					select user_id, github_user_id
					from zecret.user
					where github_user_id in ${sql(uniq)}
				`.then((xs) => Object.fromEntries(xs.map((x) => [x.github_user_id, x.user_id])))

				const transformGrant = (x: Grant) =>
					x.tag !== 'GithubUserGrant'
						? x
						: ({
								tag: 'UserGrant',
								grant_level: x.grant_level,
								path: x.path,
								user_id: userIdx[x.github_user_id]
						  } as UserGrant)

				const transformGroupMember = (x: GroupMember) =>
					x.tag !== 'GroupGithubUser'
						? x
						: ({
								tag: 'GroupUser',
								group_name: x.group_name,
								user_id: userIdx[x.github_user_id]
						  } as GroupUser)

				grants = {
					add: grants.add.map(transformGrant),
					remove: grants.remove.map(transformGrant)
				}

				group_members = {
					add: group_members.add.map(transformGroupMember),
					remove: group_members.remove.map(transformGroupMember)
				}
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
							? [sql([organization_name, o.path, o.grant_level, o.user_id])]
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
						'user_id'
					)}
					on conflict do nothing
				`
			}

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

			console.log(6)

			return {
				tag: 'ManageOrganizationOk',
				value: {}
			} as ManageOrganizationOk
		})
		.catch((err) => {
			console.error(err)
			return {
				tag: 'ManageOrganizationErr',
				value: {
					message: err.message.includes('violates row-level security policy')
						? 'Insufficient Permissions'
						: 'Unknown Error'
				}
			} as ManageOrganizationResponse
		})
}
