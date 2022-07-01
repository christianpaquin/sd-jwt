import fs from 'fs';
import * as jose from 'jose';
import * as crypto from 'crypto';
import { Log, LOG_LEVEL } from './utils';

interface SD_JWT_R {
    sd_digests: any;
}

export const verifySdJwtR = async (sdJwtR: string, jwks: jose.JSONWebKeySet): Promise<string> => {
    try {
        // split JWS into header[0], payload[1], sig[2], and optionally claimData[3]
        const parts = sdJwtR.split('.');
        let svcString = undefined;
        if (parts.length === 4) {
            // extract the 4th part with the claim salts
            sdJwtR = parts.slice(0,3).join('.');
            svcString = Buffer.from(parts[3], 'base64').toString();
            Log("svc: " + svcString, LOG_LEVEL.DEBUG);
        } else if (parts.length !== 3) {
            throw new Error("Error parsing JWS");
        }
        // else it's just a normal JWS, process it normally

        let payload = "";
        try {
            const result = await jose.compactVerify(sdJwtR, jose.createLocalJWKSet(jwks));
            payload = result.payload.toString();
            Log("payload: " + payload, LOG_LEVEL.DEBUG);
        } catch (err) {
            throw new Error(`Error validating signature: ${err}`);
        }

        // only keep the disclosed claims
        // TODO: move some of that to selective-disclosure.ts
        if (svcString) {
            const payloadObject = JSON.parse(payload); 
            const sdDigests = (payloadObject as SD_JWT_R).sd_digests;
            const svc = JSON.parse(svcString);
            const disclosedClaimNames:string[] = Object.keys(svc);
            let disclosedClaims = {};
            for (let i = 0; i < disclosedClaimNames.length; i++) {
                const name = disclosedClaimNames[i];
                let claimValue;
                let digest;
                let hashInput;
                if (sdDigests.hasOwnProperty(name) && sdDigests[name as any] !== undefined) {
                    digest = sdDigests[name as any];
                }
                if (svc.hasOwnProperty(name) && svc[name as any] !== undefined) {
                    claimValue = (svc[name as any])[1];
                    hashInput = JSON.stringify(svc[name as any]);
                }
                if (hashInput && digest) {
                    const digest2 = jose.base64url.encode(crypto.createHash('sha256').update(hashInput).digest());
                    if (digest !== digest2) {
                        throw new Error('Invalid digest for claim ${name}');
                    }
                }
                Object.defineProperty(disclosedClaims, name, {value: claimValue, enumerable: true});
            }
            Object.defineProperty(payloadObject, "disclosedClaims", {value: disclosedClaims, enumerable: true});
            Log("disclosedClaims: " + JSON.stringify(disclosedClaims), LOG_LEVEL.DEBUG);

            payload = JSON.stringify(payloadObject); 
        }

        return payload;

    } catch (err) {
        throw new Error(`Can't verify the SD-JWT-R: ${err as string}`);
    }
}

export const verifyQrFiles = async (sdJwtRPath: string, jwksPath: string, outJwtPath: string): Promise<void> => {
    console.log(`Verifying SD-JWT-R from ${sdJwtRPath}`);

    if (!fs.existsSync(sdJwtRPath)) {
        throw new Error("File not found: " + sdJwtRPath);
    }

    // read the SD-JWT-R payload
    const sdjwtR = fs.readFileSync(sdJwtRPath, 'utf8');

    let jwks: jose.JSONWebKeySet;
    if (!fs.existsSync(jwksPath)) {
        throw new Error("File not found: " + jwksPath);
    }
    const jwksBytes = fs.readFileSync(jwksPath, 'utf8');
    jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;

    const payload = await verifySdJwtR(sdjwtR, jwks);

    // output the JWT
    fs.writeFileSync(outJwtPath, payload);
    console.log(`JWT written to ${outJwtPath}`);
}
