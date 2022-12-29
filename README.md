# Simple selective disclosure for JSON Web Tokens 

This project contains a reference implementation of the [Selective Disclosure JWT (SD-JWT)](https://datatracker.ietf.org/doc/html/draft-fett-selective-disclosure-jwt) specification. It code is for reference only, it shouldn't be used in production.

*** WORK IN PROGRESS ***: The implementation aims to keep up to date with the specification [published on github](https://github.com/oauth-wg/oauth-selective-disclosure-jwt/blob/master/draft-ietf-oauth-selective-disclosure-jwt.md). It currently matches the version of [December 15, 2022](https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html).

Note that all SD-JWT are encoded using the [combined format](https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-combined-format-for-present) to attach disclosures to SD-JWTs at issuance and presentations.

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

3. Optionally, run the unit tests (TODO: write more tests!)
```
npm test
```

## Usage

This section describes the command-line interface functionality of the library; corresponding functions can also be accessed through the API.

### Generate issuer keys

To generate an issuer signing key pair, run

```
npm run generate-issuer-keys -- -k <jwksPath> -p <privatePath> -a <keyAlg>
```

where `jwksPath` is the path to the JWKS file to add the public key (creates it if doesn't exist), `privatePath` is the path to the output private key file, and `keyAlg` is the algorithm of the key to create (must be a valid [JWS alg value](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1); default is `ES256`).

### Issue a SD-JWT

To create a SD-JWT from a set of claims, run 


```
npm run create-sd-jwt -- -k <privateKeyPath> -t <jwtPath> -h <hashAlg> -c <sdClaimsPath> -o <outPath>
```

where `privateKeyPath` is the path to the issuer private signing key, `jwtPath` is the path to the source JWT to transform into a SD-JWT, `hashAlg` is the hash algorithm to use, `sdClaimsPath` is the path to the input selectively-disclosable claim values, and `outPath` is path to the output SD-JWT.

### Selectively-disclosure of claims

To selectively disclose some claims, run

```
npm run disclose-claims -- -t <sdjwtPath> -c <claims...>  -o <outPath>
```

where `sdjwtPath` is the path to the input SD-JWT, `claims...` are a series of space-separated claim names to disclose, and `outPath` is the path to the output SD-JWT with hidden claims.

### Verification of a SD-JWT-R

To verify a SD-JWT, run

```
npm run verify-sd-jwt -- -t sdJwtPath -k jwksPath -o outJwtPath -d outDisclosedPath
```

where 
`sdJwtPath` is the path to the input SD-JWT, `jwksPath` is the path to the JWKS file containing the issuer public key, `outJwtPath` is the path to the output JWT (payload of the JWS), and `outDisclosedPath` is the path to the output disclosed claims.

## Example

The following steps give an end-to-end example on how to use the library, using test data.

1. Issuer create its signing key pair (of default ES256 algorithm type)

```
npm run generate-issuer-keys -- -k jwks.json -p private.json
```

2. Issuer creates the SD-JWT

```
npm run create-sd-jwt -- -k private.json -t examples/jwt.json -c examples/sdClaimsFlat.json -o sd-jwt.json
```

3. User selectively disclose some claims and updates the SD-JWT

```
npm run disclose-claims -- -t sd-jwt.json -c given_name email -o user-sd-jwt.json
```

4. Verifier verifies the SD-JWT-R

```
npm run verify-sd-jwt -- -t user-sd-jwt.json -k jwks.json -o outJwt.json -d disclosedClaims.json
```
