import { Command } from 'commander';
import { generateIssuerKeysFiles } from './generate-issuer-keys';

const DEFAULT_KEY_ALG = "ES256";

interface Options {
    jwksPath: string;
    privatePath: string;
    keyAlg: string;
}

// process options
const program = new Command();
program.option('-k, --jwksPath <jwksPath>', "path to the JWKS file to add the public key; create it if doesn't exist");
program.option('-p, --privatePath <privatePath>', "path to the output private key file");
program.option('-a, --keyAlg <keyAlg>', `key algorithm; defaults to ${DEFAULT_KEY_ALG}`, DEFAULT_KEY_ALG);
program.parse(process.argv);
const options = program.opts() as Options;
if (!options.jwksPath) {
    options.jwksPath = "jwks.json";
}

void (async () => {
    try {
        await generateIssuerKeysFiles(options.privatePath, options.jwksPath, options.keyAlg);
    } catch (err) {
        console.log(err);
    }
})();