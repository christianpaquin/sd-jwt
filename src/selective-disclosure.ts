import * as crypto from 'crypto';
import * as jose from 'jose';

export interface sdDigests {

}

export interface ClaimDigestResults {
    svc: any; // how to specify multiple keys with ClaimData values
    sdDigests: sdDigests;
}

const SALT_BYTE_SIZE = 128 / 8; // 128-bit salts

export const createClaimDigests = (claimValues: any): ClaimDigestResults => {
    let svc = {};
    let sdDigests = {};
    const names = Object.keys(claimValues);
    const values: string[] = Object.values(claimValues);
    const salts: Buffer[] = names.map(v => crypto.randomBytes(SALT_BYTE_SIZE));
    for (let i = 0; i < names.length; i++) {
        if (typeof values[i] === 'object') {
            // create digests and svc recursively for objects
            const svc = createClaimDigests(values[i]);
            Object.defineProperty(svc, names[i], {value: svc.svc, enumerable: true});
            Object.defineProperty(sdDigests, names[i], {value: svc.sdDigests, enumerable: true});
        } else {
            const claimData = [jose.base64url.encode(salts[i]), values[i]];
            const hashInput = JSON.stringify(claimData);
            Object.defineProperty(svc, names[i], {value: claimData, enumerable: true});
            const b64Digest = jose.base64url.encode(crypto.createHash('sha256').update(hashInput).digest());
            Object.defineProperty(sdDigests, names[i], {value: b64Digest, enumerable: true});
        }
    }
    return {svc: svc, sdDigests: sdDigests};
}

