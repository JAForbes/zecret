import { tokenBoilerPlate } from './util.js'

export type CreateGroupCommand = {
	tag: 'CreateGroupCommand'
	value: {
		organization_name: string
		group_name: string
		token: string
		users: {
			add: string[]
		}
	}
}
export type CreateGroupOk = {
	tag: 'CreateGroupOk'
	value: {}
}
export type CreateGroupErr = {
	tag: 'CreateGroupErr'
	value: {
		message: string
	}
}
export type CreateGroupResponse = CreateGroupOk | CreateGroupErr

export default async function CreateGroupCommand(
	command: CreateGroupCommand
): Promise<CreateGroupResponse> {
	const [error, data] = await tokenBoilerPlate(
		(message) =>
			({ tag: 'CreateGroupErr', value: { message } } as CreateGroupErr),
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

			await sql`
				insert into zecret.group 
				${sql(command.value, 'group_name', 'organization_name')}
				on conflict do nothing
			`

			await sql`
				insert into zecret.group_user(
					organization_name, group_name, user_id
				)

				select 
					${command.value.organization_name}
					, ${command.value.group_name}
					, U.user_id
				from unnest(${command.value.users.add}::uuid[]) U(user_id)
				on conflict do nothing
			`

			return {
				tag: 'CreateGroupOk',
				value: {}
			} as CreateGroupOk
		})
		.catch((err) => {
			console.error(err)
			return {
				tag: 'CreateGroupErr',
				value: {
					message: err.message.includes('violates row-level security policy')
						? 'Insufficient Permissions'
						: 'Unknown Error'
				}
			} as CreateGroupResponse
		})
}
