import Fastify from 'fastify'
import postgres from 'postgres'
import assert from 'node:assert'
import jwt from 'jsonwebtoken'
import dedent from 'dedent-js'
import PgBoss from 'pg-boss'

assert(process.env.API_DATABASE_URL)
assert(process.env.ZECRET_API_TOKEN_SECRET)
assert(process.env.POSTMARK_API_URL)
assert(process.env.BOSS_DATABASE_URL)
assert(process.env.BASE_URL)

const { POSTMARK_API_URL, BASE_URL, ZECRET_API_TOKEN_SECRET } = process.env

const app = Fastify({ logger: true })
const sql = postgres(process.env.API_DATABASE_URL)
const boss = new PgBoss(process.env.BOSS_DATABASE_URL)

app.post<{
	Body: { email: string; user_id: string }
}>('/api/users', async (req, res) => {
	if (!(req.body.email && req.body.user_id)) {
		return res
			.status(400)
			.send({ message: 'Expected: { email: string, user_id: string }' })
	}

	const [exists] = await sql`
		select user_id from zecret.user
		where email = ${req.body.email}
	`

	email: {
		if (exists) {
			break email
		}
		const {
			username: fromUser,
			password: apiToken,
			hostname: fromHost,
			pathname
		} = new URL(POSTMARK_API_URL)
		const messageStream = pathname.slice(1)
		const magicToken = jwt.sign(
			{
				signup: true,
				sub: req.body.email,
				user_id: req.body.user_id
			},
			ZECRET_API_TOKEN_SECRET
		)
		const magicLink = new URL(BASE_URL)
		magicLink.pathname = `/api/users/verify/${magicToken}`

		await boss.send('email', {
			From: `${fromUser}@${fromHost}`,
			To: req.body.email,
			Subject: 'Welcome to Zecret',
			TextBody: dedent`
					Hi ${req.body.user_id},

					Thank you for signing up for Zecret.

					Please click this link to confirm you are a real person.

					${magicLink}

					If you did not create this account simply ignore this email
					no account has actually been created until this link is clicked.

					You can reply to this email if you'd like to ask any questions.

					Thanks!

					James (and the Zecret team)
				`,
			MessageStream: messageStream
		})
	}
	return { message: 'yay' }
})

app.get<{
	Params: { token: string }
}>('/api/users/verify/:token', async (req, res) => {
	let decoded: { sub: string; user_id: string }
	try {
		decoded = jwt.verify(req.params.token, process.env.ZECRET_API_TOKEN_SECRET)
	} catch (e) {
		return res.redirect(
			Object.assign(new URL('error', process.env.ZECRET_BASE_URL + '/'), {
				search: new URLSearchParams({ reason: 'verify-token-expired' })
			}) + ''
		)
	}
	await sql`
		insert into zecret.user ${sql({
			user_id: decoded.user_id,
			email: decoded.sub
		})}
		on conflict do nothing
	`
	return { message: 'OK' }
})

app.delete<{
	Body: { email: string }
}>('/api/users', async (req, res) => {
	if (!req.body.email) {
		return res.status(400).send({ message: 'Expected: { email: string }' })
	}
	const [, token] = req.headers.authorization?.split('Bearer ') ?? []
	if (!token) {
		return res.status(403).send({ message: 'A valid bearer token is required' })
	}

	let decoded: { admin: boolean; sub?: string }
	try {
		decoded = jwt.verify(token, process.env.ZECRET_API_TOKEN_SECRET)
	} catch (e) {
		return res.status(403).send({ message: 'A valid bearer token is required' })
	}

	if (decoded.admin || req.body.email === decoded.sub) {
		await sql`
			delete from zecret.user
			where email = ${req.body.email}
		`
		return { message: 'OK' }
	}
	return res
		.status(403)
		.send({ message: 'Not authorized to perform this action' })
})

const start = async () => {
	try {
		await boss.start()
		await app.listen({
			port: Number(process.env.PORT) || 8080,
			host: '::'
		})

		Object.keys({
			SIGHUP: 1,
			SIGINT: 2,
			SIGTERM: 15
		}).forEach((signal) => {
			process.on(signal, () => {
				app.close(() => {
					process.exit(128)
				})
			})
		})
	} catch (err) {
		console.log(err)
		process.exit(1)
	}
}

start()
