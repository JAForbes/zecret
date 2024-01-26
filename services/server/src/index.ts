import Fastify from 'fastify'

const app = Fastify({ logger: true })

app.post('/api/users', (req, res) => {
	return { message: 'yay' }
})

app.delete('/api/users', (req, res) => {
	return { message: 'yay' }
})

const start = async () => {
	try {
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
				app.close(() => {
					process.exit(128)
				})
			})
		})
	} catch (err) {
		console.log(err)
		process.exit(1)
	}
}

start()
