import fs from 'fs';
import * as jose from 'jose';
import { createClaimDigests } from './selective-disclosure';
import { Log, LOG_LEVEL } from './utils';

const createSdJwt = async (jwkJson: jose.JWK, jwt: any, claimValues: any | undefined): Promise<string> => {
    try {
        let b64claimData: string = '';
        if (claimValues) {
            const result = createClaimDigests(claimValues);
            Object.defineProperty(jwt, "sd_digests", {value: result.sdDigests, enumerable: true});
            b64claimData = jose.base64url.encode(Buffer.from(JSON.stringify(result.svc)));
        }
        // add sd_hash_alg claim
        Object.defineProperty(jwt, "sd_hash_alg", {value: "sha-256", enumerable: true}); // TODO: generalize to other hash functions

        const jwtString = JSON.stringify(jwt);
        Log("JWT: " + jwtString, LOG_LEVEL.DEBUG);
        const payload = Buffer.from(jwtString);
        Log("JWS payload: " + payload.toString("hex").toUpperCase(), LOG_LEVEL.DEBUG);

        const jwk = await jose.importJWK(jwkJson, 'ES256'); // TODO: generalize to other key types
        let jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(jwk);
        if (b64claimData) {
            jws = jws.concat('.', b64claimData);
        }
        Log("JWS: " + jws, LOG_LEVEL.DEBUG);

        return jws;
    } catch (err) {
        throw new Error(`Can't create SD-JWT code: ${err as string}`);
    }
}

export const createSdJwtFiles = async (privateKeyPath: string, jwtPath: string, sdClaimsPath: string, outPath: string): Promise<void> => {
    Log(`Creating SD-JWT from the JWT ${jwtPath} using the private key ${privateKeyPath}, encoding selectively-disclosable claims from ${sdClaimsPath}`, LOG_LEVEL.INFO);

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
    const sdJwt = await createSdJwt(jwkJson, jwt, sdClaims);
    fs.writeFileSync(outPath, sdJwt);
    Log(`SD-JWT written to ${outPath}`, LOG_LEVEL.INFO);
}
