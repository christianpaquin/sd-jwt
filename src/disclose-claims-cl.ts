import { Command } from 'commander';
import { discloseClaimsFiles } from './disclose-claims';

const DEFAULT_OUTPUT_PATH = "out-sd-jwt.json";

interface Options {
    sdjwtPath: string;
    claims: string[];
    outPath: string;
}

// process options
const program = new Command();
program.requiredOption('-t, --sdjwtPath <sdjwtPath>', 'path to the input SD-JWT');
program.requiredOption('-c, --claims <claims...>', 'name of claims to disclose');
program.option('-o, --outPath <outPath>', 'path to the output SD-JWT with hidden claims', DEFAULT_OUTPUT_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await discloseClaimsFiles(options.sdjwtPath, options.claims, options.outPath);
    } catch (err) {
        console.log(err);
    }
})();