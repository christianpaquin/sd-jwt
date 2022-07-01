import { Command } from 'commander';
import { createSdJwtFiles } from './create-sd-jwt';
import { Log, LOG_LEVEL } from './utils';

interface Options {
    privateKeyPath: string;
    jwtPath: string;
    sdClaimsPath: string;
    outPath: string;
}
const DEFAULT_OUTPUT_PATH = "sd-jwt.json";

// process options
const program = new Command();
program.requiredOption('-k, --privateKeyPath <privateKeyPath>', 'path to the issuer signing secret key file');
program.requiredOption('-t, --jwtPath <jwtPath>', 'path to the JWT in which to add a "_sd" property');
program.option('-c, --sdClaimsPath <sdClaimsPath>', 'path to the input claim values object');
program.option('-o, --outPath <outPath>', 'path to the output SD-JWT');
program.parse(process.argv);
const options = program.opts() as Options;
if (!options.outPath) {
    options.outPath = DEFAULT_OUTPUT_PATH;
}

void (async () => {
    try {
        await createSdJwtFiles(options.privateKeyPath, options.jwtPath, options.sdClaimsPath, options.outPath);
    } catch (err) {
        Log(err, LOG_LEVEL.ERROR);
    }
})();