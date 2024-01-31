import Fastify, { FastifyRequest } from 'fastify'
import postgres, { Row, TransactionSql } from 'postgres'
import assert from 'node:assert'
import jwt from 'jsonwebtoken'
import dedent from 'dedent-js'
import PgBoss from 'pg-boss'

assert(process.env.API_DATABASE_URL)
assert(process.env.ZECRET_API_TOKEN_SECRET)
assert(process.env.POSTMARK_API_URL)
assert(process.env.BOSS_DATABASE_URL)
assert(process.env.ZECRET_BASE_URL)

const { POSTMARK_API_URL, ZECRET_BASE_URL, ZECRET_API_TOKEN_SECRET } =
	process.env

const app = Fastify({ logger: true })
const sql = postgres(process.env.API_DATABASE_URL)
const boss = new PgBoss(process.env.BOSS_DATABASE_URL)

app.get('/auth/verify', (req, res) => {
	let [, token] = req.headers.authorization?.split('Bearer ') ?? []

	if (!token) {
		return res.status(403).send({ message: 'A valid bearer token is required' })
	}

	let decoded: { superuser?: boolean; sub?: string; user_id?: string }
	try {
		decoded = jwt.verify(
			token,
			process.env.ZECRET_API_TOKEN_SECRET!
		) as typeof decoded

		res.header('x-email', decoded.sub ?? '')
		res.header('x-superuser', decoded.superuser ?? 'false')
		res.header('x-user-id', decoded.user_id ?? '')
		return res.status(200).send({})
	} catch (e) {
		return res.status(403).send({ message: 'A valid bearer token is required' })
	}
})

app.post<{
	Body: { email: string; user_id: string }
}>('/users', async (req, res) => {
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
			hostname: fromHost,
			pathname
		} = new URL(POSTMARK_API_URL)
		const messageStream = pathname.slice(1)
		const token = jwt.sign(
			{
				signup: true,
				sub: req.body.email,
				user_id: req.body.user_id
			},
			ZECRET_API_TOKEN_SECRET,
			{
				expiresIn: '7 days'
			}
		)
		const magicLink = new URL(ZECRET_BASE_URL)
		magicLink.pathname = `/api/users/verify`
		magicLink.searchParams.set('token', token)

		await boss.send('email', {
			magicLink,
			postmarkRequest: {
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
			}
		})
	}
	return { message: 'job-created' }
})

app.get<{
	Querystring: { token: string }
}>('/users/verify', async (req, res) => {
	let decoded: { sub: string; user_id: string }
	try {
		decoded = jwt.verify(
			req.query.token,
			process.env.ZECRET_API_TOKEN_SECRET!
		) as typeof decoded
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
	return res.redirect(
		Object.assign(new URL('success', process.env.ZECRET_BASE_URL + '/'), {
			search: new URLSearchParams({ reason: 'user-account-created' })
		}) + ''
	)
})

app.delete<{
	Body: { email: string }
	Headers: {
		'x-email': string
		'x-user-id': string
		'x-superuser'?: 'true' | 'false'
	}
}>('/users', async (req, res) => {
	if (!req.body || !req.body.email) {
		return res.status(400).send({ message: 'Expected: { email: string }' })
	}

	if (
		req.headers['x-superuser'] == 'true' ||
		req.body.email === req.headers['x-email']
	) {
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

const withRLS = <U extends Row[]>(
	req: FastifyRequest<{
		Headers: {
			'x-email': string
			'x-user-id': string
			'x-superuser'?: 'true' | 'false'
		}
	}>,
	cb: (s: TransactionSql) => Promise<U> | Promise<void>
): ReturnType<typeof sql.begin> => {
	const out = sql.begin(async (sql) => {
		await sql`select 
			set_config('zecret.email', ${req.headers['x-email']}, true),
			set_config('zecret.user_id', ${req.headers['x-user-id']}, true),
			set_config('zecret.superuser', ${req.headers['x-superuser'] ?? ''}, true),
		`

		return cb(sql)
	})

	return out
}

type AuthHeaders = {
	'x-email': string
	'x-user-id': string
	'x-superuser'?: 'true' | 'false'
}

app.delete<{
	Body: { org_id: string }
	Headers: AuthHeaders
}>('/orgs', async (req, res) => {
	await withRLS(req, async (sql) => {
		await sql`
			delete from zecret.org
			where org_id = ${req.body.org_id}
			and (${req.headers['x-superuser'] == 'true'} or
				primary_owner = (
					select user_id from zecret.user
					where email = ${req.headers['x-email']}
				)
			)
		`
	})

	return { message: 'OK' }
})

app.get('/health', { logLevel: 'warn' }, () => {
	return {
		message: 'healthy'
	}
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
				console.log('SIGNAL', signal)
				process.exit(128)
			})
		})
	} catch (err) {
		console.log(err)
		process.exit(1)
	}
}

start()
