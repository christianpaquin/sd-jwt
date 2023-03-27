import * as sd from '../src/selective-disclosure';
import { verifyDisclosures } from '../src/verify-sd-jwt';

https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-creating-disclosures
test("disclosure encoding", async () => {
    // example from section 5.1.1.1, two dots &#168 variation
    const example = ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"];
    const expectedDisclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd";
    const actualDisclosure = sd.encodeDisclosure(example);
    expect(actualDisclosure).toBe(expectedDisclosure);
});

// https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-hashing-disclosures
test("disclosure hashing", async () => {
    // example from section 5.1.1.2
    const d = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    const expectedDigest = "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY";
    const actualDigest = sd.hashDisclosure("sha256", d);
    expect(actualDigest).toBe(expectedDigest);

});

// https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-example-1-sd-jwt
test("Example 1: SD-JWT", async () => {
    const disclosures = [
        "WyJyU0x1em5oaUxQQkRSWkUxQ1o4OEtRIiwgInN1YiIsICJqb2huX2RvZV80MiJd",
        "WyJhYTFPYmdlUkJnODJudnpMYnRQTklRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
        "WyI2VWhsZU5HUmJtc0xDOFRndTh2OFdnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
        "WyJ2S0t6alFSOWtsbFh2OWVkNUJ1ZHZRIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
        "WyJVZEVmXzY0SEN0T1BpZDRFZmhPQWNRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ",
        "WyJOYTNWb0ZGblZ3MjhqT0FyazdJTlZnIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
        "WyJkQW9mNHNlZTFGdDBXR2dHanVjZ2pRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0"
    ]
    const _sd = [
        "5nXy0Z3QiEba1V1lJzeKhAOGQXFlKLIWCLlhf_O-cmo",
        "9gZhHAhV7LZnOFZq_q7Fh8rzdqrrNM-hRWsVOlW3nuw",
        "S-JPBSkvqliFv1__thuXt3IzX5B_ZXm4W2qs4BoNFrA",
        "bviw7pWAkbzI078ZNVa_eMZvk0tdPa5w2o9R3Zycjo4",
        "o-LBCDrFF6tC9ew1vAlUmw6Y30CHZF5jOUFhpx5mogI",
        "pzkHIM9sv7oZH6YKDsRqNgFGLpEKIj3c5G6UKaTsAjQ",
        "rnAzCT6DTy4TsX9QCDv2wwAE4Ze20uRigtVNQkA52X0"
    ]
    const expectedClaims = {
        "sub": "john_doe_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "address": {"street_address": "123 Main St", "locality": "Anytown", "region": "Anystate", "country": "US"},
        "birthdate": "1940-01-01"
    }
    const claims = verifyDisclosures(disclosures, "sha256", _sd);
    expect(JSON.stringify(expectedClaims)).toBe(JSON.stringify(claims));
    console.log(claims);
});

const example_2_disclosures = [
    "WyIzWFQxYV8tOFBRNFlweEZnczRiUG9RIiwgInN1YiIsICI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiXQ",
    "WyJ3M3RSbkptLTZ4YXhtMHdWVFMxYV9nIiwgImdpdmVuX25hbWUiLCAiXHU1OTJhXHU5MGNlIl0",
    "WyJGM3MxUENGOUt3eklEaUtKajZrekpRIiwgImZhbWlseV9uYW1lIiwgIlx1NWM3MVx1NzUzMCJd",
    "WyJpQl9adWNHQ3dmampRald5MEV0RVlnIiwgImVtYWlsIiwgIlwidW51c3VhbCBlbWFpbCBhZGRyZXNzXCJAZXhhbXBsZS5qcCJd",
    "WyJMR3hTaXJELTdsRHB6SWlsVHpYdXdnIiwgInBob25lX251bWJlciIsICIrODEtODAtMTIzNC01Njc4Il0",
    "WyJlT1hQUDJNYTAzNTNiai1qLTVPRGFnIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlx1Njc3MVx1NGVhY1x1OTBmZFx1NmUyZlx1NTMzYVx1ODI5ZFx1NTE2Y1x1NTcxMlx1ZmYxNFx1NGUwMVx1NzZlZVx1ZmYxMlx1MjIxMlx1ZmYxOCIsICJsb2NhbGl0eSI6ICJcdTY3NzFcdTRlYWNcdTkwZmQiLCAicmVnaW9uIjogIlx1NmUyZlx1NTMzYSIsICJjb3VudHJ5IjogIkpQIn1d",
    "WyJwN3dJOHpfenlzQUN4ODVYOTgtWmFRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0"
];

const example_2_expectedClaims = {
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "given_name": "\u592a\u90ce",
    "family_name": "\u5c71\u7530",
    "email": "\"unusual email address\"@example.jp",
    "phone_number": "+81-80-1234-5678",
    "address": {"street_address": "\u6771\u4eac\u90fd\u6e2f\u533a\u829d\u516c\u5712\uff14\u4e01\u76ee\uff12\u2212\uff18", "locality": "\u6771\u4eac\u90fd", "region": "\u6e2f\u533a", "country": "JP"},
    "birthdate": "1940-01-01"
  }

// https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-example-2a-handling-structu
test("Example 2a: Handling Structured Claims", async () => {
    const _sd = [
        "-rAXuBrq1MIGJnPr_vGdgVhinHfvtw6HMvkMQ6rk1Po",
        "ZRtxg42klTl-Ap_OiwNVh49ZCGM059AmHPayFqbMilE",
        "g_WrTVyjFFsppeKOjcgAK8nLTeY8IcPAYSz00xNn5Rk",
        "hblncirSgqjt8gTQ56jy7FUd1cpCg0orxca0C-o9aoo",
        "lagH02GaboFAO6_d2R8jpdjO-Xxnh4aVAG9cE8iV4Sg",
        "p3vzUx7kYcA_dOlOQpyf8Z8J4s1ZPfhXWZNFuI4JgvU",
        "s2OMJlfL0E9i46-mM3sQKxJ0bEs3bNwBrzXhObM7iR0"
      ]
      const claims = verifyDisclosures(example_2_disclosures, "sha256", _sd);
      expect(JSON.stringify(example_2_expectedClaims)).toBe(JSON.stringify(claims));
 
});

/* Currently failing. I think it's a spec issue. See https://github.com/oauth-wg/oauth-selective-disclosure-jwt/issues/240
// https://drafts.oauth.net/oauth-selective-disclosure-jwt/draft-ietf-oauth-selective-disclosure-jwt.html#name-example-2b-adding-decoys
test("Example 2b: Adding Decoys", async () => {
    const _sd = [ // TODO: are these correct? 2a's _sd should be a subset of these
        "Bjq8C3IYd_T7sPnFaLW0rFxcGS38tFaF4N04yxPapPM",
        "CumxYvjP8bktgbI_AE6JNVCqAMu-WIqgl-uiXb0MdVU",
        "E02ULAmabgHhofkyV8ity0bGQxknP_OwHuYk9pO91a8",
        "Gb99XLWQ8dw3a6Mb6pbbzojv-JUr9mLifcPekGqfoN8",
        "kEII5g1ez1VcLVApcjmUmZnYG2VRA8IxFBi0Q0FhLzc",
        "x2i1zOePQ8VpoceJa_-Ln89TD7d-Px4BAY4G9sjELNk",
        "z2WPjyH1cG3pwqhHVm89iX3gW82VmOV_0VlzMb0c0oQ",
        "zA3zOqIDbohbtOInLFK9Qju1mbndVtawOdZkCyUoxmg",
        "zPd_yrC5okdqofSD68hXpdR5UNkPr5N71UVaE-jcUYM"
      ]
      const claims = verifyDisclosures(example_2_disclosures, "sha256", _sd);
      expect(JSON.stringify(example_2_expectedClaims)).toBe(JSON.stringify(claims));
});
*/
