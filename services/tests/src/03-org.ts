import test from 'node:test'
import assert from 'assert'
import postgres from 'postgres'
import jwt from 'jsonwebtoken'

assert(process.env.API_DATABASE_URL)
assert(process.env.ZECRET_API_TOKEN_SECRET)

const orgsEndpoint = new URL('orgs', process.env.ZECRET_API_URL + '/')

const SUPERUSER_TOKEN = jwt.sign(
	{
		sub: 'admin@zecret.local',
		admin: true
	},
	process.env.ZECRET_API_TOKEN_SECRET
)

const sql = await postgres(process.env.API_DATABASE_URL, {
	idle_timeout: 0.1,
	connect_timeout: 0.1,
	keep_alive: 0,
	max: 1,
	max_lifetime: 1
})

test.before(
	() =>
		sql`
		insert into zecret.user
		${sql([
			{
				email: 'james@example.com',
				user_id: 'jmsfbs'
			},
			{
				email: 'emmanuel@example.com',
				user_id: 'eja'
			}
		])}
		on conflict do nothing
	`
)
test.before(async () => {
	console.log(orgsEndpoint)
	const res = await fetch(orgsEndpoint, {
		method: 'DELETE',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${SUPERUSER_TOKEN}`
		},
		body: JSON.stringify({
			org_id: 'harth'
		})
	})
	console.log(await res.text())
	// assert(res.ok)
})
test('org', async (t) => {
	console.log('hello', orgsEndpoint)
})

test.after(
	() => sql`
		delete from zecret.user
	`
)
