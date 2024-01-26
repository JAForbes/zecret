export const name = 'Initial Schema'

export const teardown = async (sql) => {
	const { username } = new URL(process.env.API_DATABASE_URL)
	await sql`
		drop role ${sql(username)};
	`.catch((err) => console.error(err))
}
export const action = async (sql, { roles }) => {
	const { username, password } = new URL(process.env.API_DATABASE_URL)
	await sql`
		create role ${sql(username)} with login password '${sql(password)}';
	`
}
