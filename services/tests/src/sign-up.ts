import assert from 'node:assert'
import test from 'node:test'

assert(process.env.ZECRET_API_URL)

const usersEndpoint = new URL('users', process.env.ZECRET_API_URL + '/')

console.log(usersEndpoint + '')
test.before(async () => {
	const res = await fetch(usersEndpoint, {
		method: 'DELETE',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			email: 'james@harth.io',
			username: 'jmsfbs'
		})
	})

	assert(res.ok, 'User deleted')
})

test('sign-up', async (t) => {
	// we need to create an account, we use our email

	const res = await fetch(usersEndpoint, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			email: 'james@harth.io',
			username: 'jmsfbs'
		})
	})
	assert(res.ok)

	const { message }: { message: string } = await res.json()
	assert(message)
})
