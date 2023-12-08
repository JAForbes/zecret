import assert from "assert"

export const test = (name, fn) => async (sql) => {
	return sql
		.begin(async (sql) => {
			await sql`
				set role zecret_api
			`
			await fn(sql)
			throw new Error("Intentional Rollback")
		})
		.catch((err) => {
			if (err.message.includes("Intentional")) {
				return
			} else {
				console.error("Test failed", name)
				throw err
			}
		})
}

export function inspectErr(sql, fn) {
	return sql
		.savepoint((sql) => fn(sql))
		.then(
			(data) => [null, data],
			(err) => [err, null]
		)
}

export async function expectErr(sql, fn, pattern) {
	{
		const [err, data] = await inspectErr(sql, fn)

		assert.match(err?.message, pattern)
	}
}
