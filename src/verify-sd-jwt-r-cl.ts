import { Command } from 'commander';
import { verifyQrFiles } from './verify-sd-jwt-r';

interface Options {
    sdJwtRPath: string;
    jwksPath: string;
    outJwtPath: string;
}
const DEFAULT_JWT_PATH = "jwt.json";

// process options
const program = new Command();
program.requiredOption('-t, --sdJwtRPath <sdJwtRPath>', 'path to the input SD-JWT-R');
program.option('-k, --jwksPath <jwksPath>', "path to the JWKS file containing the issuer public key");
program.option('-o, --outJwtPath <outJwtPath>', 'path to the output JWT', DEFAULT_JWT_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await verifyQrFiles(options.sdJwtRPath, options.jwksPath, options.outJwtPath);
    } catch (err) {
        console.log(err);
    }
})();