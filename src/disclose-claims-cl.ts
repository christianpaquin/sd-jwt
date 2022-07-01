import { Option, Command } from 'commander';
import { discloseClaimsFiles } from './disclose-claims';

const DEFAULT_OUTPUT_PATH = "out-sd-jwt.json";

interface Options {
    sdjwtPath: string;
    claims: string[];
    sdjwtRPath: string;
}

// process options
const program = new Command();
program.requiredOption('-t, --sdjwtPath <sdjwtPath>', 'path to the input SD-JWT');
program.requiredOption('-c, --claims <claims...>', 'name of claims to disclose');
program.option('-r, --sdjwtRPath <sdjwtRPath>', 'path to the output SD-JWT-R with hidden claims', DEFAULT_OUTPUT_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await discloseClaimsFiles(options.sdjwtPath, options.claims, options.sdjwtRPath);
    } catch (err) {
        console.log(err);
    }
})();