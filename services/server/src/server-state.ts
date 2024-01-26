import postgres from 'postgres'
export type Config = {
	BASE_URL: string
	POSTMARK_URL: string
}

export type BufferKeyPair = {
	private_key: Buffer
	public_key: Buffer
	server_public_key_id: string
}

export type ActiveState = {
	state: 'active'
	key_pairs: BufferKeyPair[]
	token_secret: string
	postgres: ReturnType<typeof postgres>
}
export type IdleState = {
	state: 'idle'
}

export type State = (IdleState | ActiveState) & { config: Config }

const config: Config = {
	BASE_URL: process.env.BASE_URL as string,
	POSTMARK_URL: process.env.POSTMARK_URL
}
export let state: State = { state: 'idle', config }

export const replaceState = (_state: State): void => {
	state = { ..._state, config }
}
