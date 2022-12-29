import { Command } from 'commander';
import { verifySdJwtFile } from './verify-sd-jwt';

interface Options {
    sdJwtPath: string;
    jwksPath: string;
    outJwtPath: string;
    outDisclosedPath: string;
}
const DEFAULT_OUT_JWT_PATH = "jwt.json";
const DEFAULT_OUT_DISCLOSED_PATH = "disclosed.json"

// process options
const program = new Command();
program.requiredOption('-t, --sdJwtPath <sdJwtPath>', 'path to the input SD-JWT');
program.option('-k, --jwksPath <jwksPath>', "path to the JWKS file containing the issuer public key");
program.option('-o, --outJwtPath <outJwtPath>', 'path to the output JWT', DEFAULT_OUT_JWT_PATH);
program.option('-d, --outDisclosedPath <outDisclosedPath>', 'path to the output disclosed claims', DEFAULT_OUT_DISCLOSED_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await verifySdJwtFile(options.sdJwtPath, options.jwksPath, options.outJwtPath, options.outDisclosedPath);
    } catch (err) {
        console.log(err);
    }
})();