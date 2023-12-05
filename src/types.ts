export type KeyPair = {
	private_key: string;
	public_key: string;
};

export type BufferKeyPair = {
	private_key: Buffer;
	public_key: Buffer;
};

export type DecryptedToken = {
	gh: {
		username: string;
	};

	shared_cipher: string;

	public_key_hash: string;

	// when the token was issued
	iat: number;

	// at this point check github still lists that key
	// that's it, no need to log the user out
	exp: number;
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

export type EncryptedSecretRequestObject = {
	path: string;

	key: string;

	enc_value: string;
};

export type PutCommand = {
	tag: "Put";
	value: {
		public_key: string;
		secrets: EncryptedSecretRequestObject[];
	};
};

export type InitializeStoreCommand = {
	tag: "InitializeStore";
	value: {
		key_pair: KeyPair;
		token_secret: string;
	};
};

export type InitializeStoreOk = {
	tag: "InitializeStoreOk";
	value: {};
};

export type InitializeStoreErr = {
	tag: "InitializeStoreErr";
	value: {
		message: string;
	};
};

export type InitializeStoreResponse = InitializeStoreOk | InitializeStoreErr;

export type RollServerKeyPairCommand = {
	tag: "RollServerKeyPair";
	value: {
		old_private_key: string;
		new_private_key: string;
		new_public_key: string;
	};
};

export type * from "./server-login";
export type * from "./server-whoami";
export type * from "./server-token-refresh";

export type Command = LoginCommand | InitializeStoreCommand;
