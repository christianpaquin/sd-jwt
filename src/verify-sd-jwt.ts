import fs from 'fs';
import * as jose from 'jose';
import { Log, LOG_LEVEL } from './utils';
import { DisclosureArray, hashDisclosure, parseDisclosure } from './selective-disclosure';

interface SD_JWT {
    _sd: string[];
    _sd_alg: string;
}

interface VERIFYSDJWT_RETURN {
    jwt: string;
    disclosed: string;
}

export const verifyDisclosures = (disclosures: string[], sd_alg: string, sd: string[]): any => {
    let disclosedClaims = {};
    disclosures.forEach(disclosure => {
        const disclosureDigest = hashDisclosure(sd_alg, disclosure);
        if (!sd.includes(disclosureDigest)) {
            throw new Error(`Disclosure ${disclosure} is not contained in SD-JWT`);
        }
        const disclosureArray = parseDisclosure(disclosure);
        Object.defineProperty(disclosedClaims, disclosureArray[DisclosureArray.NAME], {value: disclosureArray[DisclosureArray.VALUE], enumerable: true});
    })
    return disclosedClaims;
}

export const verifySdJwt = async (sdJwt: string, jwks: jose.JSONWebKeySet): Promise<VERIFYSDJWT_RETURN> => {
    try {
        // split SD-JWS into JWS and Disclosures
        const parts = sdJwt.split('~');
        const JWS = parts[0];

        // verify the JWS
        let payload = "";
        try {
            const result = await jose.compactVerify(JWS, jose.createLocalJWKSet(jwks));
            payload = result.payload.toString();
            Log("payload: " + payload, LOG_LEVEL.DEBUG);
        } catch (err) {
            throw new Error(`Error validating signature: ${err}`);
        }

        // verify the Disclosures, if any
        // TODO: generalized for nested objects
        let disclosedClaims = {};
        if (parts.length > 1) {
            const disclosures = parts.slice(1);
            const payloadObject = JSON.parse(payload);
            const sd = (payloadObject as SD_JWT)._sd;
            const sd_alg = (payloadObject as SD_JWT)._sd_alg;
            disclosedClaims = verifyDisclosures(disclosures, sd_alg, sd);
        }

        const disclosedClaimsString = JSON.stringify(disclosedClaims);
        Log("disclosedClaims: " + disclosedClaimsString, LOG_LEVEL.DEBUG);
        return {
            jwt: payload,
            disclosed: disclosedClaimsString
        };

    } catch (err) {
        throw new Error(`Can't verify the SD-JWT: ${err as string}`);
    }
}


export const verifySdJwtFile = async (sdJwtPath: string, jwksPath: string, outJwtPath: string, outDisclosedPath: string): Promise<void> => {
    console.log(`Verifying SD-JWT from ${sdJwtPath}`);

    if (!fs.existsSync(sdJwtPath)) {
        throw new Error("File not found: " + sdJwtPath);
    }

    // read the SD-JWT payload
    const sdjwt = fs.readFileSync(sdJwtPath, 'utf8');

    let jwks: jose.JSONWebKeySet;
    if (!fs.existsSync(jwksPath)) {
        throw new Error("File not found: " + jwksPath);
    }
    const jwksBytes = fs.readFileSync(jwksPath, 'utf8');
    jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;

    const rv = await verifySdJwt(sdjwt, jwks);

    // output the JWT
    fs.writeFileSync(outJwtPath, rv.jwt);
    console.log(`JWT written to ${outJwtPath}`);

    // output the disclosed claims
    fs.writeFileSync(outDisclosedPath, rv.disclosed);
    console.log(`JWT written to ${outDisclosedPath}`);
}
