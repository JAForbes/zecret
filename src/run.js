import minimist from "minimist";
import { $, fs } from "zx";

const argv = minimist(process.argv.slice(2), { "--": true });

async function dev() {
	await fs.rmdir("./dist", { recursive: true }).catch(() => {});
	await fs.mkdir("./dist", { recursive: true }).catch(() => {});
	await fs.writeFile("./dist/package.json", JSON.stringify({}));
	await fs.writeFile("./dist/index.js", "");

	const esbuildProc = $`npx esbuild src/index.ts --sourcemap --outfile=dist/index.js --bundle --watch --platform=node`;
	const nodeWatchProc = $`(cd dist; node --enable-source-maps --watch index.js ${argv["--"]})`;

	await Promise.all([esbuildProc, nodeWatchProc]);
}

await { dev }[argv._[0]]?.(argv, argv._.slice(1));
