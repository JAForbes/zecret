export const name = 'Initial Schema'

export const teardown = async (sql) => {
	for (let [url] of [
		[process.env.API_DATABASE_URL, 'api'],
		[process.env.BOSS_DATABASE_URL, 'boss']
	]) {
		const { username } = new URL(url)

		await sql`
			drop owned by ${sql(username)}
		`.catch((err) => console.error(err))
		await sql`
			drop role ${sql(username)};
		`.catch((err) => console.error(err))
	}
}

export const action = async (sql, { roles }) => {
	let users = {}
	let database
	for (let [url, name] of [
		[process.env.API_DATABASE_URL, 'api'],
		[process.env.BOSS_DATABASE_URL, 'boss']
	]) {
		const { username, password, pathname } = new URL(url)
		await sql`
			create role ${sql(username)} with inherit login password '${sql(password)}';
		`
		users[name] = username
		database = pathname.slice(1)
	}

	await sql`
		create extension if not exists citext with schema public;
	`

	await sql`
		grant create on database ${sql(database)} to ${sql(users.boss)}
	`

	await await sql`
		create schema if not exists zecret;
	`

	await sql`
		grant usage on schema zecret to ${sql(roles.service)}
	`

	await sql`
		grant usage on schema zecret to ${sql(users.api)}
	`

	await sql`
		create table zecret.user(
			user_id public.citext primary key
			, email public.citext not null unique
		);
	`

	await sql`
		grant select, insert, update, delete on zecret.user to ${sql(roles.service)}
	`

	await sql`
		grant ${sql(roles.service)} to ${sql(users.api)}
	`
}
