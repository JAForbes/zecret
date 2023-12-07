import minimist from "minimist";
import cli from "./cli";
import server from "./server";

type Mode = "server" | "cli";

const argv = minimist(process.argv.slice(2));

const mode: Mode = argv._.find((x) => x === "serve") ? "server" : "cli";

const commands = {
	server,
	cli,
} as const;

const command = commands[mode];

command(argv).catch((e) => {
	console.error(e);
	process.exitCode = 1;
});
