import * as jose from 'jose';
import fs from 'fs';

export interface GenerateIssuerKeysResult {
    jwks: jose.JSONWebKeySet;
    privateJwk: jose.JWK;
}

export const generateIssuerKeys = async (jwks: jose.JSONWebKeySet | undefined, keyAlg: string): Promise<GenerateIssuerKeysResult> => {
    try {
        if (!jwks) {
            // create a new JWKS
            jwks = {keys: []};
        }
        
        // generate the key pair
        const { publicKey, privateKey } = await jose.generateKeyPair(keyAlg);
        const privateJwk = await jose.exportJWK(privateKey);
        const publicJwk = await jose.exportJWK(publicKey);
        
        // calculate the key identifier (kid) thumbprint and add it to the key pair
        const kid = await jose.calculateJwkThumbprint(publicJwk,'sha256');
        const addKeyProperty = (jwk: jose.JWK, kid: string) => {
            jwk.kid = kid;
            jwk.use = "sig";
            jwk.alg = keyAlg;
        }
        addKeyProperty(privateJwk, kid);
        addKeyProperty(publicJwk, kid);

        jwks.keys.push(publicJwk);
        
        return {
            jwks: jwks,
            privateJwk: privateJwk
        };
    } catch (err) {
        throw new Error(`Can't generate issuer keys: ${err as string}`);
    }
}

export const generateIssuerKeysFiles = async (privatePath: string, jwksPath: string, keyAlg: string): Promise<void> => {
    console.log("Generating issuer keys");

    let jwks: jose.JSONWebKeySet | undefined;
    let jwksUpdate = false;
    if (fs.existsSync(jwksPath)) {
        // read the JWKS file to update
        const jwksBytes = fs.readFileSync(jwksPath, 'utf8');
        jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;
        jwksUpdate = true;
    }
    
    const result = await generateIssuerKeys(jwks, keyAlg);

    // write out updated JWKS        
    fs.writeFileSync(jwksPath, JSON.stringify(result.jwks, null, 4));
    console.log(`Public JWKS ${jwksUpdate ? 'added' : 'written'} to ${jwksPath}`);

    // write out private key
    if (!privatePath) {
        privatePath = `${result.privateJwk.kid}.json`;
    }
    fs.writeFileSync(privatePath, JSON.stringify(result.privateJwk, null, 4));
    console.log(`Private key written to ${privatePath}`);
}
