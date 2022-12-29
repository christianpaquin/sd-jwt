import { Command } from 'commander';
import { createSdJwtFile } from './create-sd-jwt';
import { Log, LOG_LEVEL } from './utils';

interface Options {
    privateKeyPath: string;
    jwtPath: string;
    hashAlg: string;
    sdClaimsPath: string;
    outPath: string;
}

const DEFAULT_HASH_ALG = "sha-256";
const DEFAULT_OUTPUT_PATH = "sd-jwt.json";

// process options
const program = new Command();
program.requiredOption('-k, --privateKeyPath <privateKeyPath>', 'path to the issuer signing secret key file');
program.requiredOption('-t, --jwtPath <jwtPath>', 'path to the JWT in which to add selectively-disclosable claims');
program.option('-h, --hashAlg <hashAlg>', `the hash algorithm to use; defaults to ${DEFAULT_HASH_ALG}`, DEFAULT_HASH_ALG);
program.option('-c, --sdClaimsPath <sdClaimsPath>', 'path to the input claim values object');
program.option('-o, --outPath <outPath>', 'path to the output SD-JWT', DEFAULT_OUTPUT_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await createSdJwtFile(options.privateKeyPath, options.jwtPath, options.hashAlg, options.sdClaimsPath, options.outPath);
    } catch (err) {
        Log(err, LOG_LEVEL.ERROR);
    }
})();