export type BufferKeyPair = {
	private_key: Buffer;
	public_key: Buffer;
};

export type State =
	| {
			state: "idle";
	  }
	| {
			state: "active";
			key_pairs: BufferKeyPair[];
			token_secret: string;
	  };

export let state: State = { state: "idle" };

export const replaceState = (_state: State): void => {
	state = _state;
};
