import test from 'node:test'
import assert, { rejects } from 'node:assert'

import postgres, { Sql, TransactionSql } from 'postgres'

const SQL = postgres(process.env.TEST_DATABASE_URL as string)

interface Begin {
	begin<T>(fn: (sql: TransactionSql) => T): ReturnType<typeof SQL.begin>
}

const AsUser = (begin: Begin['begin'], users: Users) => {
	const asUser = (user: keyof Users) => (fn: Parameters<typeof begin>[0]) =>
		begin(async (sql) => {
			await sql`select zecret.set_active_user(${users[user]})`

			return fn(sql)
		})

	return asUser
}

type Users = {
	JAForbes: string
	JBravoe: string
	J1Marotta: string
	bens: string
}

let state:
	| ({
			tag: 'initialized'
			server_public_key_id: string
			users: Users
			asUser: ReturnType<typeof AsUser>
	  } & Begin)
	| { tag: 'uninitialized' } = { tag: 'uninitialized' }

const afters: (() => any)[] = []

test('setup', async (t) => {
	const server_public_key_id = ''
	const begin: Begin['begin'] = <T>(fn: (sql: TransactionSql) => T) => {
		return SQL.begin(async (sql) => {
			await sql`
				set role zecret_api
			`
			await sql.savepoint((sql) => fn(sql))
			await sql`
				reset role
			`
		})
	}

	await SQL`
		insert into zecret.server_public_key(
			server_public_key_pkcs8, server_public_key_id
		) values ('', '')
		on conflict do nothing
	`
	afters.push(async () => {
		await SQL`
			delete
			from zecret.server_public_key
			where server_public_key_id = ${server_public_key_id}
		`
	})

	await SQL`
		insert into zecret.user(github_user_id) values ('JAForbes'), ('JBravoe'), ('J1marotta'), ('bens')
		on conflict do nothing
		returning user_id
	`
	afters.push(
		() => SQL`
		delete from zecret.user
		where github_user_id in ('JAForbes', 'JBravoe', 'J1marotta', 'bens')
	`
	)

	const [
		{ user_id: JAForbes },
		{ user_id: JBravoe },
		{ user_id: J1Marotta },
		{ user_id: bens }
	] = await SQL`
		select user_id from zecret.user
		where github_user_id in ('JAForbes', 'JBravoe', 'J1marotta', 'bens')
	`
	const users = {
		JAForbes,
		JBravoe,
		J1Marotta,
		bens
	}
	state = {
		tag: 'initialized',
		begin,
		asUser: AsUser(begin, users),
		server_public_key_id,
		users
	}
})

test.after(async () => {
	for (let fn of afters) {
		await fn()
	}
	SQL.end()
})

test('RLS: org and group', async (t) => {
	assert(state.tag === 'initialized')

	const { begin, users, asUser, server_public_key_id } = state

	await rejects(
		() =>
			begin(
				(sql) =>
					sql`insert into zecret.org (organization_name) values ('harth') on conflict do nothing`
			),
		/new row violates row-level security policy/
	)

	await begin(async (sql) => {
		await sql`select zecret.set_active_user(${users.JBravoe})`
		await sql`insert into zecret.org (organization_name) values ('JBravoe') on conflict do nothing`
	})

	await begin(async (sql) => {
		await sql`select zecret.set_active_user(${users.JAForbes})`
		await sql`insert into zecret.org (organization_name) values ('harth') on conflict do nothing`
	})

	const JAForbes = asUser('JAForbes')
	const JBravoe = asUser('JBravoe')
	const JM = asUser('J1Marotta')

	await JAForbes(async (sql) => {
		const xs = await sql`select * from zecret.org`
		assert.equal(
			xs.length,
			1,
			'Cannot see org if not in group associated with it'
		)
		const [{ organization_name }] = xs
		assert.equal(organization_name, 'harth')
	})

	await JAForbes(async (sql) => {
		await sql`
			insert into zecret.group(organization_name, group_name)
			values ('harth', 'developers')
			on conflict do nothing
			;
		`
	})

	await rejects(
		() =>
			JAForbes(
				(sql) => sql`
					insert into zecret.group_user(organization_name, group_name, user_id)
					values ('harth', 'developers', ${users.JBravoe})
					on conflict do nothing
				`
			),
		/new row violates row-level security policy for table "group_user"/
	)

	await JAForbes(async (sql) => {
		await sql`
			insert into zecret.org_user(organization_name, user_id)
			values ('harth', ${users.JBravoe})
			on conflict do nothing
		`
		await sql`
			insert into zecret.group_user(organization_name, group_name, user_id)
			values ('harth', 'developers', ${users.JBravoe})
			on conflict do nothing
		`
		// in practice values will be encrypted, but that is outside of
		// postgres' purview
		// JAForbes can write because he is primary owner in that org
		await sql`
			insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
				values ('harth', '/odin/zip', 'DATABASE_URL', 'postgres://zip:password@postgres:5432/postgres', '','', ${server_public_key_id})
			on conflict do nothing
		`
	})

	await rejects(
		() =>
			JBravoe(
				(sql) => sql`
				insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
					values ('harth', '/odin/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres', '','', ${server_public_key_id})
				on conflict do nothing
			`
			),
		/new row violates row-level security policy for table "secret"/
	)

	await JAForbes(
		(sql) =>
			sql`
			insert into zecret.grant_group(
				organization_name, group_name, path, grant_level
			)
			values (
				'harth', 'developers', '/odin', 'write'
			)
			on conflict do nothing
		`
	)

	// JBravoe can write a secret now to that path because of the group grant
	await JBravoe(
		(sql) =>
			sql`
			insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
			values ('harth', '/odin/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres', '','', ${server_public_key_id})
			on conflict do nothing
		`
	)

	// But writing to a different path will be rejected
	await rejects(
		() =>
			JBravoe(
				(sql) => sql`
					insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
						values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres', '','', ${server_public_key_id})
						on conflict do nothing
				`
			),
		/new row violates row-level security policy for table "secret"/
	)

	await JAForbes(
		(sql) => sql`
			insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
					values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres', '','', ${server_public_key_id})
			on conflict do nothing
		`
	)

	// JM can't write either, he is in no org or group yet
	await rejects(
		() =>
			JM(
				(sql) => sql`
				insert into zecret.secret(organization_name, path, key, value, iv, symmetric_secret, server_public_key_id)
					values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres', '','', ${server_public_key_id})
					on conflict do nothing
				`
			),
		/new row violates row-level security policy for table "secret"/
	)

	// primary owner can write to any path
	// and JM can't see any secrets

	await JM(async (sql) => {
		const xs = await sql`
			select * from zecret.secret
		`
		assert.deepEqual(xs, [], 'New user cannot see any secrets')
	})

	await JAForbes(async (sql) => {
		const xs = await sql`
			select * from zecret.secret
		`
		assert.deepEqual(
			xs.map((x) => x.path).sort(),
			['/evgen/upload', '/odin/upload', '/odin/zip'],
			'primary owner can see all secrets'
		)
	})

	await JBravoe(async (sql) => {
		const xs = await sql`
			select * from zecret.secret
		`

		assert.deepEqual(
			xs.map((x) => x.path).sort(),
			['/odin/upload', '/odin/zip'],
			'group user can see their secrets'
		)
	})
})

test('RLS: user', async (t) => {
	assert(state.tag === 'initialized')

	const { begin, users, asUser, server_public_key_id } = state

	const JAForbes = asUser('JAForbes')
	const JBravoe = asUser('JBravoe')
	const JM = asUser('J1Marotta')

	await begin(async (sql) => {
		const all = await sql`
			select * from zecret.user
			where user_id in ${sql([users.JAForbes, users.JBravoe])}
		`
		assert.equal(all.length, 2, 'Users table is public read')

		const inertUpdate = await sql`
			update zecret.user set deleted_at = now()
		`

		assert.equal(inertUpdate.count, 0, 'RLS prevented global update')
	})

	await JAForbes(async (sql) => {
		const deleteUpdate = await sql`
			update zecret.user set deleted_at = now()
		`

		assert.equal(deleteUpdate.count, 1, 'active user deleted')

		{
			const all = await sql`
				select * from zecret.user
				where user_id in ${sql([users.JAForbes, users.JBravoe])}
			`
			const remainingIds = [users.JAForbes, users.JBravoe].filter(
				(x) => x != users.JAForbes
			)
			assert.deepEqual(
				all.map((x) => x.user_id),
				remainingIds
			)
		}
	})
})
