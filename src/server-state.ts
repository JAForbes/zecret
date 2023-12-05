import { State } from "./types";

export let state: State = { state: "idle" };

export const replaceState = (_state: State): void => {
	state = _state;
};
