import assert from 'assert'
import { DecodedToken, UpsertSecret } from './types.js'
import { parseJwt, serverDecrypt, tokenBoilerPlate } from './util.js'
import { state } from './server-state.js'

type CreateOrgCommand = {
	tag: 'CreateOrgCommand'
	value: {
		organization_name: string
		token: string
	}
}
type CreateOrgOk = {
	tag: 'CreateOrgOk'
	value: {}
}
type CreateOrgErr = {
	tag: 'CreateOrgErr'
	value: {
		message: string
	}
}
type CreateOrgResponse = CreateOrgOk | CreateOrgErr

export default async function CreateOrgCommand(
	command: CreateOrgCommand
): Promise<CreateOrgResponse> {
	const [error, data] = await tokenBoilerPlate(
		(message) => ({ tag: 'CreateOrgErr', value: { message } } as CreateOrgErr),
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

			const createResult = await sql`
				insert into zecret.org(organization_name)
				values (${command.value.organization_name})
				on conflict (organization_name) do nothing
			`

			await sql`
				insert into zecret.org_user(organization_name, user_id)
				values (${command.value.organization_name}, zecret.get_active_user())
				on conflict do nothing
			`

			if (createResult.count == 0) {
				const [{ is_owner }] = await sql`
					select primary_owner_id = zecret.get_active_user() as is_owner
					from zecret.org
					where organization_name = ${command.value.organization_name}
				`.catch(() => [{ is_owner: false }])
				if (is_owner) {
					return {
						tag: 'CreateOrgOk',
						value: {}
					} as CreateOrgOk
				}
				return {
					tag: 'CreateOrgErr',
					value: {
						message: 'Organization could not be created, it may already exist'
					}
				} as CreateOrgErr
			}

			return {
				tag: 'CreateOrgOk',
				value: {}
			} as CreateOrgOk
		})
		.catch((err) => {
			console.error(err)
			return {
				tag: 'CreateOrgErr',
				value: {
					message: 'Unknown Error'
				}
			} as CreateOrgErr
		})
}
