import { Command } from 'commander';
import { generateIssuerKeysFiles } from './generate-issuer-keys';

interface Options {
    jwksPath: string;
    privatePath: string;
}

// process options
const program = new Command();
program.option('-k, --jwksPath <jwksPath>', "path to the JWKS file to add the public key; create it if doesn't exist");
program.option('-p, --privatePath <privatePath>', "path to the output private key file");
program.parse(process.argv);
const options = program.opts() as Options;
if (!options.jwksPath) {
    options.jwksPath = "jwks.json";
}

void (async () => {
    try {
        await generateIssuerKeysFiles(options.privatePath, options.jwksPath);
    } catch (err) {
        console.log(err);
    }
})();