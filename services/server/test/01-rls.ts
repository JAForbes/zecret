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
		insert into zecret.user(user_name, email, avatar_url) 
		values 
			('JAForbes','JAForbes@example.com', 'https://avatar.example.com/JAForbes')
			, ('JBravoe', 'JBravoe@example.com', 'https://avatar.example.com/JBravoe')
			, ('J1marotta', 'J1marotta', 'https://avatar.example.com/J1marotta')
			, ('bens', 'bens', 'https://avatar.example.com/bens')
		on conflict do nothing
		returning user_name
	`
	afters.push(
		() => SQL`
			delete from zecret.user
			where user_name in ('JAForbes', 'JBravoe', 'J1marotta', 'bens')
		`
	)

	await SQL`
		insert into zecret.known_key_authority_user_name(user_name, key_authority_name, key_authority_user_name) 
		values 
			('JAForbes','github','JAForbes')
			, ('JBravoe', 'github','JBravoe')
			, ('J1marotta', 'github','J1marotta')
			, ('bens', 'github','bens')
		on conflict do nothing
		returning user_name
	`

	const [
		{ user_name: JAForbes },
		{ user_name: JBravoe },
		{ user_name: J1Marotta },
		{ user_name: bens }
	] = await SQL`
		select user_name from zecret.user
		where user_name in ('JAForbes', 'JBravoe', 'J1marotta', 'bens')
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
						insert into zecret.group_user(organization_name, group_name, user_name)
						values ('harth', 'developers', ${users.JBravoe})
						on conflict do nothing
					`
			),
		/new row violates row-level security policy for table "group_user"/
	)
	await JAForbes(async (sql) => {
		await sql`
				insert into zecret.org_user(organization_name, user_name)
				values ('harth', ${users.JBravoe})
				on conflict do nothing
			`
		await sql`
				insert into zecret.group_user(organization_name, group_name, user_name)
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
				where user_name in ${sql([users.JAForbes, users.JBravoe])}
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
		const deleteUpdate2 = await sql`
			update zecret.user set deleted_at = null
		`
		assert.equal(deleteUpdate2.count, 1, 'active user undeleted')

		const deleteUpdate3 = await sql`
			update zecret.user set deleted_at = null
			where user_name <> 'JAForbes'
		`
		assert.equal(deleteUpdate3.count, 0, 'active user undeleted')
		{
			const all = await sql`
				select * from zecret.user
				where user_name in ${sql([users.JAForbes, users.JBravoe])}
			`
			assert.deepEqual(
				all.map((x) => x.user_name).sort(),
				[users.JAForbes, users.JBravoe].sort()
			)
		}
	})
})

test.after(async () => {
	for (let fn of afters) {
		await fn()
	}
	SQL.end()
})
