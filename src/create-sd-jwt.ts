import fs from 'fs';
import * as jose from 'jose';
import { createDisclosures } from './selective-disclosure';
import { Log, LOG_LEVEL } from './utils';

const createSdJwt = async (jwkJson: jose.JWK, jwt: any, hashAlg: string, claimValues: any | undefined): Promise<string> => {
    try {
        let disclosures: string[] = [];
        if (claimValues) {
            disclosures = createDisclosures(hashAlg, claimValues, jwt);
            // add _sd_alg claim
            Object.defineProperty(jwt, "_sd_alg", {value: hashAlg, enumerable: true});
        } // else just a normal JWS

        const jwtString = JSON.stringify(jwt);
        Log("JWT: " + jwtString, LOG_LEVEL.DEBUG);
        const payload = Buffer.from(jwtString);
        Log("JWS payload: " + payload.toString("hex").toUpperCase(), LOG_LEVEL.DEBUG);

        const jwk = await jose.importJWK(jwkJson, 'ES256'); // TODO: generalize to other key types
        let jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(jwk);
        if (disclosures) {
            jws = jws.concat('~' + disclosures.join('~'));
        }
        Log("JWS: " + jws, LOG_LEVEL.DEBUG);

        return jws;
    } catch (err) {
        throw new Error(`Can't create SD-JWT code: ${err as string}`);
    }
}

const SUPPORTED_IANA_HASH_ALG: string[] = ["sha-256", "sha-384", "sha-512"];

export const createSdJwtFile = async (privateKeyPath: string, jwtPath: string, hashAlg: string, sdClaimsPath: string, outPath: string): Promise<void> => {
    Log(`Creating SD-JWT from the JWT ${jwtPath} using the private key ${privateKeyPath}, encoding selectively-disclosable claims from ${sdClaimsPath}`, LOG_LEVEL.INFO);

    // check hash alg
    if (!SUPPORTED_IANA_HASH_ALG.includes(hashAlg)) {
        throw new Error(`Unsupported hash alg ${hashAlg}, must be one of: ${SUPPORTED_IANA_HASH_ALG}`);
    }
    if (!fs.existsSync(privateKeyPath)) {
        throw new Error("File not found : " + privateKeyPath);
    }
    if (!fs.existsSync(jwtPath)) {
        throw new Error("File not found : " + jwtPath);
    }
    if (!fs.existsSync(sdClaimsPath)) {
        throw new Error("File not found : " + jwtPath);
    }

    // read the private key
    const privateString = fs.readFileSync(privateKeyPath, 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync(jwtPath, 'utf8');
    const jwt = JSON.parse(jwtString);

    // read the sdClaims payload
    let sdClaims;
    if (sdClaimsPath) {
        const claimDigestsString = fs.readFileSync(sdClaimsPath, 'utf8');
        sdClaims = JSON.parse(claimDigestsString);
    }

    // create and write out the SD-JWT
    const sdJwt = await createSdJwt(jwkJson, jwt, hashAlg, sdClaims);
    fs.writeFileSync(outPath, sdJwt);
    Log(`SD-JWT written to ${outPath}`, LOG_LEVEL.INFO);
}
