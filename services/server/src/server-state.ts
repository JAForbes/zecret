import postgres from "postgres"

export type BufferKeyPair = {
	private_key: Buffer
	public_key: Buffer
	server_public_key_id: string
}

export type ActiveState = {
	state: "active"
	key_pairs: BufferKeyPair[]
	token_secret: string
	postgres: ReturnType<typeof postgres>
}
export type IdleState = {
	state: "idle"
}

export type State = IdleState | ActiveState

export let state: State = { state: "idle" }

export const replaceState = (_state: State): void => {
	state = _state
}
