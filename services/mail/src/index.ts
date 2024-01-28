import assert from 'node:assert'
import PgBoss from 'pg-boss'

assert(process.env.BOSS_DATABASE_URL)
assert(process.env.POSTMARK_API_URL)

const { password: apiToken } = new URL(process.env.POSTMARK_API_URL)

const boss = new PgBoss(process.env.BOSS_DATABASE_URL)

await boss.start()

await boss.work('email', async function sendEmail(postmarkData) {
	await fetch('https://api.postmarkapp.com/email', {
		headers: {
			'X-Postmark-Server-Token': apiToken,
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(postmarkData)
	})
})
