import assert from "assert"
import * as util from "./utils.js"

export default util.test("user-rls", async (sql) => {
	const inserts = await sql`
		insert into zecret.user(github_user_id) values ('JAForbes'), ('JBravoe') returning user_id;
	`
	const ids = inserts.map((x) => x.user_id)

	const all = await sql`
		select * from zecret.user
		where user_id in ${sql(ids)}
	`
	assert.equal(all.length, 2, "Users table is public read")

	const inertUpdate = await sql`
		update zecret.user set deleted_at = now()
	`

	assert.equal(inertUpdate.count, 0, "RLS prevented global update")

	await sql`
		select zecret.set_active_user(${ids[0]})
	`

	const [{ au }] = await sql`
		select zecret.get_active_user() as au
	`
	assert.equal(au, ids[0], "active user is set")

	const deleteUpdate = await sql`
		update zecret.user set deleted_at = now()
	`

	assert.equal(deleteUpdate.count, 1, "active user deleted")

	{
		const all = await sql`
			select * from zecret.user
		`

		const remainingIds = ids.filter((x) => x != ids[0])
		assert.deepEqual(
			all.map((x) => x.user_id),
			remainingIds
		)
	}
})
