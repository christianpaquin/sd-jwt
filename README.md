# Simple selective disclosure for JSON Web Tokens 

This project contains a reference implementation of the [Selective Disclosure JWT (SD-JWT)](https://datatracker.ietf.org/doc/html/draft-fett-selective-disclosure-jwt) specification. It code is for reference only, it shouldn't be used in production.

*** WORK IN PROGRESS ***: The implementation aims to keep up to date with the specification [published on github](https://github.com/oauthstuff/draft-selective-disclosure-jwt). It currently matches the version of Oct 8th, 2022 (commit [a9d4b5](https://github.com/oauth-wg/oauth-selective-disclosure-jwt/commit/a9d4b52d25035018350b019c928d84a3be553486)), with the following caveat:
* Blinding claim names ([PR 124](https://github.com/oauth-wg/oauth-selective-disclosure-jwt/pull/124)) is not yet supported

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/christianpaquin/sd-jwt.git
cd sd-jwt
```

2. Build the `npm` package
```
npm install
npm run build
```

3. Optionally, run the unit tests (TODO: write tests!)

```
npm test
```

## Usage

This section describes the command-line interface functionality of the library; corresponding functions can also be accessed through the API.

### Generate issuer keys

To generate an issuer signing key pair (currently hardcoded to an ECDSA P-256 key), run

```
npm run generate-issuer-keys -- -k <jwksPath> -p <privatePath>
```

where `jwksPath` is the path to the JWKS file to add the public key (creates it if doesn't exist), and `privatePath` is the path to the output private key file.

### Issue a SD-JWT

To create a SD-JWT from a set of claims, run 


```
npm run create-sd-jwt -- -k <privateKeyPath> -t <jwtPath> -c <sdClaimsPath> -o <outPath>
```

where `privateKeyPath` is the path to the issuer private signing key, `jwtPath` is the path to the source JWT to transform into a SD-JWT, `sdClaimsPath` is the path to the input selectively disclosable claim values, and `outPath` is path to the output SD-JWT.

### Selectively-disclosure of claims

To selectively disclose some claims, run

```
npm run disclose-claims -- -t <sdjwtPath> -c <claims...>  -r <sdjwtRPath>
```

where `sdjwtPath` is the path to the input SD-JWT, `claims...` are a series of space-separated claim names to disclose, and `sdjwtRPath` is the path to the output SD-JWT-R with hidden claims.

### Verification of a SD-JWT-R

To verify a SD-JWT-R, run

```
npm run verify-sd-jwt-r -- -t sdJwtRPath -k jwksPath -o outJwtPath
```

where 
`sdJwtRPath` is the path to the input SD-JWT-R, `jwksPath` is the path to the JWKS file containing the issuer public key, and `outJwtPath` is the path to the output JWT where the disclosed claims have been encoded.

## Example

The following steps give an end-to-end example on how to use the library, using test data.

1. Issuer create its signing key pair

```
npm run generate-issuer-keys -- -k jwks.json -p private.json
```

2. Issuer creates the SD-JWT

```
npm run create-sd-jwt -- -k private.json -t examples/jwt.json -c examples/sdClaimsFlat.json -o sd-jwt.json
```

3. User selectively disclose some claims and creates the SD-JWT-R

```
npm run disclose-claims -- -t sd-jwt.json -c given_name email -r sd-jwt-r.json
```

4. Verifier verifies the SD-JWT-R

```
npm run verify-sd-jwt-r -- -t sd-jwt-r.json -k jwks.json -o outJwt.json
```
