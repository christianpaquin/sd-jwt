import * as crypto from 'crypto';
import * as jose from 'jose';

export enum DisclosureArray {
    SALT=0, NAME=1, VALUE=2
}

const SALT_BYTE_SIZE = 128 / 8; // 128-bit salts

// create disclosures for selectively-disclosable claims, and adds the sd digests into the SD-JWT (target)
export const createDisclosures = (hashAlg: string, claimValues: any, target: any): string[] => {
    let disclosures: string[] = [];
    let sdDigests: string[] = [];
    const names = Object.keys(claimValues);
    const values: string[] = Object.values(claimValues);
    const salts: Buffer[] = names.map(v => crypto.randomBytes(SALT_BYTE_SIZE));
    for (let i = 0; i < names.length; i++) {
        if (typeof values[i] === 'object') {
            // create _sd recursively for nested objects TODO
            throw new Error("Not yet implemented");
        } else {
            // encode the salt using base64-url, as recommended by the spec
            const disclosureArray = [jose.base64url.encode(salts[i]), names[i], values[i]];
            const disclosure = encodeDisclosure(disclosureArray);
            disclosures.push(disclosure);
            const disclosureDigest = hashDisclosure(hashAlg, disclosure);
            sdDigests.push(disclosureDigest);
        }
    }
    // add _sd property
    Object.defineProperty(target, "_sd", {value: sdDigests.sort(), enumerable: true}); // sort the sd values as recommended by the spec

    return disclosures;
}

export const encodeDisclosure = (disclosureArray: string[]): string => {
    return jose.base64url.encode(JSON.stringify(disclosureArray))
}

// return the hash algorithm for the node crypto module api, lowercase, no hyphens
// e.g., 'SHA-256' --> 'sha256'
// TODO: this only works for the SHA2 family; the crypto module uses openssl names, a mapping
//       table should be used to support more algs (e.g., from the SHA3 family)
const ianaToCryptoAlg = (hashAlg: string): string => hashAlg.replace('-', '').toLowerCase(); 

export const hashDisclosure = (alg: string, disclosure: string): string => {
    return jose.base64url.encode(crypto.createHash(ianaToCryptoAlg(alg)).update(disclosure).digest());
}
export const parseDisclosure = (disclosure: string): string[] => {
    const input = jose.base64url.decode(disclosure);
    const parsed: string[] = JSON.parse(Buffer.from(input).toString());
    if (parsed.length != 3) {
        throw new Error("can't parse disclosure: " + disclosure);
    }
    return parsed;
}