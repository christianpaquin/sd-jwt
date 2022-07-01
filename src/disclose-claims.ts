import fs from 'fs';
import * as jose from 'jose';
import { Log, LOG_LEVEL } from './utils';

const discloseClaims = async (sdJwt: string, claims: string[]): Promise<string> => {
    // extract 4th part containing the claims data
    const parts = sdJwt.split('.');
    if (parts.length !== 4) {
        throw new Error("Error parsing SD-JWT, no SVC found (4th part)");
    }

    let svcString = Buffer.from(parts[3], 'base64').toString();
    Log("svc: " + svcString, LOG_LEVEL.DEBUG);
    const svc = JSON.parse(svcString);

    // remove the undisclosed claims
    let claimNames = Object.keys(svc);
    claimNames.forEach(name => {
        if (!claims.includes(name)) {
            delete svc[name];
        }
    })
    svcString = JSON.stringify(svc)
    Log("updated svc: " + svcString, LOG_LEVEL.DEBUG);

    // re-encode the updated claims data
    const updatedSvc = jose.base64url.encode(svcString);
    parts[3] = updatedSvc;
    sdJwt = parts.join('.');

    return sdJwt;
}

export const discloseClaimsFiles = async (sdjwtPath: string, claims: string[], sdjwtRPath: string): Promise<void> => {
    console.log(`Disclosing claims ${claims} from SD-JWT ${sdjwtPath}`);

    if (!fs.existsSync(sdjwtPath)) {
        throw new Error("File not found: " + sdjwtPath);
    }
    
    // read the SD-JWT payload
    const sdjwt = fs.readFileSync(sdjwtPath, 'utf8');

    // only disclose the specified claims
    const sdJwtR = await discloseClaims(sdjwt, claims);
    fs.writeFileSync(sdjwtRPath, sdJwtR);
    console.log(`Selectively-disclosed SD-JWT-R written to ${sdjwtRPath}`);
}