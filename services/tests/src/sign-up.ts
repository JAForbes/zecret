import assert from 'node:assert'
import test from 'node:test'
import jwt from 'jsonwebtoken'
import postgres from 'postgres'

assert(process.env.ZECRET_API_URL)
assert(process.env.ZECRET_API_TOKEN_SECRET)
assert(process.env.BOSS_DATABASE_URL)

const usersEndpoint = new URL('users', process.env.ZECRET_API_URL + '/')
const bossSQL = await postgres(process.env.BOSS_DATABASE_URL, {
	idle_timeout: 0.1,
	connect_timeout: 0.1,
	keep_alive: 0,
	max: 1,
	max_lifetime: 1
})

const SUPERUSER_TOKEN = jwt.sign(
	{
		sub: 'admin@zecret.fly.dev',
		admin: true
	},
	process.env.ZECRET_API_TOKEN_SECRET
)

test.before(async () => {
	const res = await fetch(usersEndpoint, {
		method: 'DELETE',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${SUPERUSER_TOKEN}`
		},
		body: JSON.stringify({
			email: 'james@harth.io'
		})
	})

	assert(res.ok, 'User deleted')

	{
		const sql = bossSQL
		await sql`
			delete
			from pgboss.job
			where name = 'email'
		`
	}
})

test('sign-up', async (t) => {
	// we need to create an account, we use our email

	const res = await fetch(usersEndpoint, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			email: 'james@harth.io',
			user_id: 'jmsfbs'
		})
	})
	console.log(await res.text())
	assert(res.ok)

	// const { message }: { message: string } = await res.json()
	// assert(message)

	{
		const sql = bossSQL
		const tasks = await sql`
			select * 
			from pgboss.job
			where name = 'email'
		`
		assert.equal(tasks.count, 1)
	}
})
