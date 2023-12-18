import { tokenBoilerPlate } from './util.js'

export type Group = {
	group_name: string
	organization_name: string
	users: string[]
}
export type ListGroupCommand = {
	tag: 'ListGroupCommand'
	value: {
		organization_name: string
		token: string
	}
}
export type ListGroupOk = {
	tag: 'ListGroupOk'
	value: {
		groups: Group[]
	}
}
export type ListGroupErr = {
	tag: 'ListGroupErr'
	value: {
		message: string
	}
}
export type ListGroupResponse = ListGroupOk | ListGroupErr

export default async function ListGroupCommand(
	command: ListGroupCommand
): Promise<ListGroupResponse> {
	const [error, data] = await tokenBoilerPlate(
		(message) => ({ tag: 'ListGroupErr', value: { message } } as ListGroupErr),
		command.value.token
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

			const groups = await sql<Group[]>`
				select G.*, array_agg(GU.user_id) as users
				from zecret.group G
				inner join zecret.group_user GU using (organization_name, group_name)
				where organization_name = ${command.value.organization_name}
				group by G.organization_name, G.group_name
			`
			return {
				tag: 'ListGroupOk',
				value: {
					groups
				}
			} as ListGroupOk
		})
		.catch((err) => {
			return {
				tag: 'ListGroupErr',
				value: {
					message: err.message.includes('violates row-level security policy')
						? 'Insufficient Permissions'
						: 'Unknown Error'
				}
			} as ListGroupResponse
		})
}
