import assert from "assert"
import * as util from "./utils.js"

export default util.test("org and group rls", async (sql) => {
	const [
		{ user_id: JAForbes },
		{ user_id: JBravoe },
		{ user_id: JM },
		{ user_id: bens }
	] = await sql`
		insert into zecret.user(github_user_id) values ('JAForbes'), ('JBravoe'), ('J1marotta'), ('bens')
		returning user_id
	`

	await util.expectErr(
		sql,
		(sql) => sql`insert into zecret.org (organization_name) values ('harth')`,
		/new row violates row-level security policy/
	)

	await sql`select zecret.set_active_user(${JBravoe})`
	await sql`insert into zecret.org (organization_name) values ('JBravoe')`

	await sql`select zecret.set_active_user(${JAForbes})`
	await sql`insert into zecret.org (organization_name) values ('harth')`

	{
		const xs = await sql`select * from zecret.org`
		assert.equal(
			xs.length,
			1,
			"Cannot see org if not in group associated with it"
		)

		const [{ organization_name }] = xs
		assert.equal(organization_name, "harth")
	}

	await sql`
		insert into zecret.group(organization_name, group_name) 
		values ('harth', 'developers');
	`

	await util.expectErr(
		sql,
		(sql) =>
			sql`
				insert into zecret.group_user(organization_name, group_name, user_id)
				values ('harth', 'developers', ${JBravoe})
			`,
		/new row violates row-level security policy for table "group_user"/
	)

	await sql`
		insert into zecret.org_user(organization_name, user_id)
		values ('harth', ${JBravoe})
	`

	await sql`
		insert into zecret.group_user(organization_name, group_name, user_id)
		values ('harth', 'developers', ${JBravoe})
	`

	// in practice values will be encrypted, but that is outside of
	// postgres' purview

	// JAForbes can write because he is primary owner in that org
	await sql`
		insert into zecret.secret(organization_name, path, key, value)
			values ('harth', '/odin/zip', 'DATABASE_URL', 'postgres://zip:password@postgres:5432/postgres')
	`

	await sql`select zecret.set_active_user(${JBravoe})`

	// JBravoe is in the org, and in the developers group
	// but there is no grant to write at that path yet
	await util.expectErr(
		sql,
		(sql) => sql`
			insert into zecret.secret(organization_name, path, key, value)
				values ('harth', '/odin/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
		`,
		/new row violates row-level security policy for table "secret"/
	)

	await sql`select zecret.set_active_user(${JAForbes})`

	await sql`
		insert into zecret.grant_group(
			organization_name, group_name, path, grant_level
		)
		values (
			'harth', 'developers', '/odin', 'write'
		)
	`

	await sql`select zecret.set_active_user(${JBravoe})`

	// JBravoe can write a secret now to that path because of the group grant
	await sql`
		insert into zecret.secret(organization_name, path, key, value)
			values ('harth', '/odin/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
	`

	// But writing to a different path will be rejected
	await util.expectErr(
		sql,
		(sql) => sql`
			insert into zecret.secret(organization_name, path, key, value)
				values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
		`,
		/new row violates row-level security policy for table "secret"/
	)

	// But writing to a different path will be rejected
	await util.expectErr(
		sql,
		(sql) => sql`
			insert into zecret.secret(organization_name, path, key, value)
				values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
		`,
		/new row violates row-level security policy for table "secret"/
	)

	await sql`select zecret.set_active_user(${JAForbes})`
	await sql`
		insert into zecret.secret(organization_name, path, key, value)
				values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
	`

	await sql`select zecret.set_active_user(${JM})`

	// JM can't write either, he is in no org or group yet
	await util.expectErr(
		sql,
		(sql) => sql`
			insert into zecret.secret(organization_name, path, key, value)
				values ('harth', '/evgen/upload', 'DATABASE_URL', 'postgres://upload:password@postgres:5432/postgres')
		`,
		/new row violates row-level security policy for table "secret"/
	)

	// primary owner can write to any path
	// and JM can't see any secrets
	{
		const xs = await sql`
			select * from zecret.secret
		`
		assert.deepEqual(xs, [], "New user cannot see any secrets")
	}

	{
		await sql`select zecret.set_active_user(${JAForbes})`
		const xs = await sql`
			select * from zecret.secret
		`

		assert.deepEqual(
			xs.map((x) => x.path).sort(),
			["/evgen/upload", "/odin/upload", "/odin/zip"],
			"primary owner can see all secrets"
		)
	}

	{
		await sql`select zecret.set_active_user(${JBravoe})`
		const xs = await sql`
			select * from zecret.secret
		`

		assert.deepEqual(
			xs.map((x) => x.path).sort(),
			["/odin/upload", "/odin/zip"],
			"group user can see their secrets"
		)
	}
})
