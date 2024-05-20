import { describe, expect, test } from "bun:test";
import { b64utohex, utf8tohex, zulutosec } from "typepki-strconv";
import { getHMACKey, importPEM } from "typepki-webcrypto";
import { JWTVerifyOption, signJWS, verifyJWS, verifyJWT } from "./index.mts";

describe("signJWS", async () => {
  test("RFC 7797 4.1 HS256 example", async () => {
    const key = await getHMACKey("hmacSHA256", JWS9741KEYHEX);
    expect(await signJWS("HS256", key, JWSHEAD9741, JWSPAY9741)).toBe(JWS9741);
  });
  test("RFC 7515 A.1 HS256 example", async () => {
    const key = await getHMACKey("hmacSHA256", b64utohex(JWSKEYA1B64U));
    expect(await signJWS("HS256", key, JWSHEADA1, JWSPAYA1)).toBe(JWSA1);
  });
  test("RFC 7515 A.2 RS256 example", async () => {
    const prvkey = await importPEM(PRVPEMA2, "SHA256withRSA");
    expect(await signJWS("RS256", prvkey, JWSHEADA2, JWSPAYA2)).toBe(JWSA2);
  });
});

describe("verifyJWS", async () => {
  test("RFC 7797 4.1 HS256 example", async () => {
    const key = await getHMACKey("hmacSHA256", JWS9741KEYHEX);
    expect(await verifyJWS(JWS9741, key)).toBe(true);
  });
  test("RFC 7515 A.1 HS256 example", async () => {
    const key = await getHMACKey("hmacSHA256", b64utohex(JWSKEYA1B64U));
    expect(await verifyJWS(JWSA1, key)).toBe(true);
  });
  test("RFC 7515 A.2 RS256 example", async () => {
    const pubkey = await importPEM(PUBPEMA2, "SHA256withRSA");
    expect(await verifyJWS(JWSA2, pubkey)).toBe(true);
  });
  test("RFC 7515 A.3 ES256 example", async () => {
    const pubkey = await importPEM(PUBPEMA3, "SHA256withECDSA", "P-256");
    expect(await verifyJWS(JWSA3, pubkey)).toBe(true);
  });
  test("RFC 7515 A.4 ES512 example", async () => {
    const pubkey = await importPEM(PUBPEMA4, "SHA512withECDSA", "P-521");
    expect(await verifyJWS(JWSA4, pubkey)).toBe(true);
  });
  test("PS256 with RFC 9500 TEST KEY RSA2048 jwt.io", async () => {
    const pubkey = await importPEM(JWSPS256R2PUB, "SHA256withRSAandMGF1");
    expect(await verifyJWS(JWSPS256R2, pubkey)).toBe(true);
  });
  test("acceptAlgs option test - HS256 not in [RS256]", async () => {
    const key = await getHMACKey("hmacSHA256", b64utohex(JWSKEYA1B64U));
    expect(async () => {
      await verifyJWS(JWSA1, key, ["RS256"]);
    }).toThrow(/not accepted/);
  });
});

describe("signJWS and verifyJWS", async () => {
  test("ES256", async () => {
    const prvkey = await importPEM(PRVPEMA3, "SHA256withECDSA", "P-256");
    const sJWS = await signJWS("ES256", prvkey, JWSHEADA3, JWSPAYA3);
    const pubkey = await importPEM(PUBPEMA3, "SHA256withECDSA", "P-256");
    expect(await verifyJWS(sJWS, pubkey)).toBe(true);
  });
  test("ES512", async () => {
    const prvkey = await importPEM(PRVPEMA4, "SHA512withECDSA", "P-521");
    const sJWS = await signJWS("ES512", prvkey, JWSHEADA4, JWSPAYA4);
    const pubkey = await importPEM(PUBPEMA4, "SHA512withECDSA", "P-521");
    expect(await verifyJWS(sJWS, pubkey)).toBe(true);
  });
  test("PS256", async () => {
    const prvkey = await importPEM(JWSPS256R2PRV, "SHA256withRSAandMGF1");
    const sJWS = await signJWS("PS256", prvkey, JWSPS256R2HEAD, JWSPS256R2PAY);
    const pubkey = await importPEM(JWSPS256R2PUB, "SHA256withRSAandMGF1");
    expect(await verifyJWS(sJWS, pubkey)).toBe(true);
  });
});

// == RFC 7515 JWS EXAMPLES A.1 HS256 =================================
const JWSHEADA1 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

const JWSPAYA1 =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

const JWSA1 =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const JWSKEYA1B64U =
  "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

// == RFC 7797 4.1 HS256 example ======================================
const JWSHEAD9741 = "eyJhbGciOiJIUzI1NiJ9";
const JWSPAY9741 = "JC4wMg";
const JWS9741 =
  "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
const JWS9741KEYHEX =
  "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

// == RFC 7515 JWS EXAMPLES A.2 RS256 =================================
// RFC 7515 A.2 sample RS256 JWS header
const JWSHEADA2 = "eyJhbGciOiJSUzI1NiJ9";

// RFC 7515 A.2 sample RS256 JWS payload
const JWSPAYA2 =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

// RFC 7515 A.2 sample RS256 JWS signature
const JWSA2 =
  "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

// RFC 7515 A.2 RFC 7515 A.2 sample RSA private key
const PRVPEMA2 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCh+BYK4uPJtGXO
jS1lYmM2K5J9vinh8CR3/BYlzJChNuOL2TSXxbbqY913EeZ8dCn5VrD7io8ImtxL
aYk8wTM/U+3QGbh3hCUv7JFP5IV3aVlL6kKA0ywPVb9ilE8TA5a8bpvfbr3SvaNn
juygxmj3AbONv/s4yDQs4v5tJ/reSlpIdJed1LnPmt7Ex1sFhSwsD174pcF1A5L5
ROjtZMEQxrZHYJqkeDrrnGya11UxMFBji4NmXG9veoKjlnAqH2QbgtPr8jkiGUkf
toaHLFcW9Qr4NY2ai50Xw0Byj3+H2JoY2PyrZ62EWQwuz3WTOTY8BwNNb2BvniHg
VFbK5emhAgMBAAECggEAEq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyW
PEAeP88vLNO97IjlA7/GQ5sLKMgvfTeXZx9SE+7YwVol2NXOoAJe46sui395IW/G
O+pWJ1O0BkTGoVEn2bKVRUCgu+GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzj
kn439X0M/V51gfpRLI9JYanrC4D4qAdGcopV/0ZHHzQlBjudU2QvXt4ehNYTCBr6
XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl/x/jTj3ccPDVZFD9pIuhLhBOneufuBiB
4cS98l2SR/RQyGWSeWjnczT0QU91p1DhOVRuOopznQKBgQDgHMQQ60imZV1URk0K
pLttoLhyt3SmqdEf/kgHePDdtzEafpAu+cS191R2JiuoF2yzWXnwFDcqGigp5BNr
0AHQfD8/Lk8l1Mk09jxxCfui5nYooNyac8YFjm3vItzVCVDnEd3BbVWG8qf6deqE
lMGAg+C2V0L4oNXnP7LZcPAZRwKBgQC5A8R+CZW2MvRTLLHzwZkUXV866cff7tx6
kqa0finGG0KgeqlaZPxgCZnFp7AeAcCMtiynVlJ7vMVgePsLq6XtON4tB5kP9jAP
rq3rbAOal78eUH5OcED6eNuCV8ixEu1eWcPNCS/l1OW1EnXUEoEHKl54Xrrz2uNw
kgMTP1FZ1wKBgAcCn1dwJKufzBWQxWQp1vsM5fggqPN1qGb5y0MAk3g7/Ls5bkUp
5u9SN0Ai3Ya6hNnvWJMb7sXQX6U/zyO2M/hTip7tUeh7CXgwo59dkpN75gJLVds2
9+DAncu3KXU4f2Fa+7bLNrur53k8KwPOq2bbuTG69QtV7Jr5MR0AHWKNAoGBAIf/
evpitUf+4JYbLpvNXWcY052Mpz22aR84mY3nh3F2LF2mjMJDpTg7FmuyPcVw6EcG
yoAe9fa65iNqCq+jdw6PVNGo2hxfjSiZ8IIzHdsPXI89//pMjZcQK9r+CCoRjaZj
OYiIDktVWZzmevJuv6WywUqd57LE3Zar3dLSIkx1AoGAIYd7DHOhrWvxkwPQsRM2
tOgrjbcrfvtQJipd+DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd/QJQ3
ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp/gh6A56
03k2+ZQwVK0JKSHuLFkuQ3U=
-----END PRIVATE KEY-----`;

const PUBPEMA2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofgWCuLjybRlzo0tZWJj
NiuSfb4p4fAkd/wWJcyQoTbji9k0l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEz
P1Pt0Bm4d4QlL+yRT+SFd2lZS+pCgNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo
9wGzjb/7OMg0LOL+bSf63kpaSHSXndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTB
EMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxX
FvUK+DWNmoudF8NAco9/h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXp
oQIDAQAB
-----END PUBLIC KEY-----`;

// == RFC 7515 JWS EXAMPLES A.3 ES256 =================================
const JWSHEADA3 = "eyJhbGciOiJFUzI1NiJ9";

const JWSPAYA3 =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

const JWSA3 =
  "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

const PRVPEMA3 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjpsQnnGQmL+YBIff
H1136cspYG6+0iY7X1fCE9+E9LKhRANCAAR/zc4ncPbEXUGDy+5v20t7WAczNXvp
7xO6z248e9FURcfxRM0bvZt+hyzf7bnuufSzaV1uqQskrYpGIyiFiOWt
-----END PRIVATE KEY-----`;

const PUBPEMA3 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7
6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==
-----END PUBLIC KEY-----`;

// == RFC 7515 JWS EXAMPLES A.4 ES512 =================================
const JWSHEADA4 = "eyJhbGciOiJFUzUxMiJ9";

const JWSPAYA4 = "UGF5bG9hZA";

const JWSA4 =
  "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";

const PRVPEMA4 = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBjmlvsDRQWIHdEQtI
Prh9Ms5JX+NrN0Xt8tjK5PDyU59GFaDpjqtSs8DF6sTOB1GFqOe7R96sHR3ne8z2
YTXmPYKhgYkDgYYABAHpKQUPEk/GvFXH1TkzZd+d70qwwiyyV5j5NOsE48a643Aa
V6eRDp2BvzYxWejryxVdY0n0vbbM+KlMXFnHqsEBpAA0pkQON2dQ0jcf0b3CyPO3
HS9O5eo0MsgVzKMVYP5dk4fsd0tVg4Yw5cu/Woy+CpHdAGTGmZofbm5n+t3t5MjI
9g==
-----END PRIVATE KEY-----`;

const PUBPEMA4 = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB6SkFDxJPxrxVx9U5M2Xfne9KsMIs
sleY+TTrBOPGuuNwGlenkQ6dgb82MVno68sVXWNJ9L22zPipTFxZx6rBAaQANKZE
DjdnUNI3H9G9wsjztx0vTuXqNDLIFcyjFWD+XZOH7HdLVYOGMOXLv1qMvgqR3QBk
xpmaH25uZ/rd7eTIyPY=
-----END PUBLIC KEY-----`;

// == PS256 with RFC 9500 TEST KEY RSA 2048 =========================
// rfc9500testkey/testrsa2048.jwtio.ps256

const JWSPS256R2HEAD = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9";

const JWSPS256R2PAY =
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";

const JWSPS256R2 =
  "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.gsglLQGIhSKRDoKFh0JjyhAMFffXtnLwLUWYtUX5tSmKxmEp9bb7oAw5m3O-KWRXLg4ARJIlB5q36E6e5FeUdyIJLujEwm_mdGrbgg9Pe2l7hKyjFAoY8_7Uroun8a3XZMvwDU-by-rTGeEYNFj4xnh3AvgSweOODAkE36kMchDixoyZ3sSwFi4ZClI2teHwu_u71-3zvAPXeJ6PcAJkN9xTaB0FuzsmzQ7DgA5z3p67BLN0FO8FZlP3lZ59HCb6nQ4oySr5w5xj2lZUu4786IfzTsF9d8BpI97e69LbE4r8l7ikfRyPRiSO2K6jqmEXNvClZWjOgj8YZKgtIZCU8Q";

const JWSPS256R2PRV = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCw+egZQ6eumJKq
3hfKfED4dE/tL4FI5sjqont9ABVI+1GSqyi1bFBgsRjM0THllIdMbKmJtWwnKW8J
+5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz0VTWdlAXXmhUs6lSADvAaIe4RVrC
sZ97L3ZQTryY7JRVcbB4khUN3Gp0yg+801SXzoFTTa+UGIRLE66jH51aa5VXu99h
nv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wHqIOOPvQcWV3M5D2vxJEj702Ku6k9
OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3dVUm+fM6NoDXPoLP7j55G9zKyqGtG
AWXAj1MTAgMBAAECggEAQRiLIM/b28LPH/51LcuqcjkGNS4mFdSdzoBZf88KBUA7
7wD6BlGC9y3s+1lvSwzo/1lwuvB6iaUZ7MgWsvT/rFBprxsGv+979rzXnk6ByMWj
p9kTDcPPutrl9tKI+a7j9v+S+uD4GvWXvslq6fq5QCzV/kH3Bb69tHu3NtP+bFpR
4OIHMql7XkbBy9sm10hUxrZgSu1GNzX/kHYEZVfK+Um/RIiVwgQyweCcAU6nVmBD
TxoPO+KUurxdUw5qECE/U7YDdfyEp1c/KvEhVYT1tL2m1Oj54Xp42X53uG2koYRk
dTGKehClYQFO/6I6gexW6eQQne+Ms/eXIj99jQ1DUQKBgQDdEFcCOC8jKzaB9TeR
4iYXx79OmsuB7Uja9taZXaPqtkKDmv8BLS6mKLkK8nn9Pm98k82A8HLwH/JEOz7o
8k7UaaeWE6Qb0kAg+S/REFm9HQ8wG1unqdNjfKjWXBqYFUF9jqtzSwtPOixmHZoa
gvOsc0xAUwZpq45HMEWljmVTnQKBgQDM8eW7kMjpeB6nW+vxC8JS4R6wI6AmDxiH
VSpWhj9KZCHoxgC/Uj1ssbCtvdZb/uSoigN+PRpBXlu5VkjaWgyia1T0pjlIUiw9
X4m5SnLv/5UTTVlAzkV1jzCJgJCJVliO71dbPkvEw2jP6BPunCUsKwLg35HxqgGT
jThoXWC6bwKBgAntVOrtmPhMVXtKhr9PV4ST3Lxr6R2hiTcEBKkIcnb0zlHYoQDt
hX3CsGSUdPPxXNJMVNsocRDlblywCGgvkWiqgfMUWLdDHswcRJBv2ofKiUcQw3Hp
B2wdSfuuUSdpNPKteHeJ9C0PoLTJOYVdQhIJb3AoCk6ufIon2cjQdy5lAoGBAIy2
hXp71UZfgAR+m4e8ACcxhAWB4GJhOQEqW1BfCjOEfre4wyiZSa1IbztLPVOatdp2
MCHLyCwbojSlZo3tCAG4WfND8c6TBOb6orACytm3jN5c3CwftBccQkIWcKarD1DM
ShlOs20ckek1ugG5Wdhyi55kQms/w6dQbetSOainAoGACoHYphgxSoA69hwGcR8s
ObJm/0FNU0dtHaUqQxiq/kuW8NoHFV+KUTTauI7inoFoB2/NeMp5GsY0Qqgc0Gk5
J9gI4zXo2MvyEhkHUJpXdZtPmhj6OnszN3nt3npFk4T4REra7P/slf1VKwz8tsf2
kmJt3h7yaKQNL2e1yKo4f/c=
-----END PRIVATE KEY-----`;

const JWSPS256R2PUB = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPnoGUOnrpiSqt4XynxA
+HRP7S+BSObI6qJ7fQAVSPtRkqsotWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTf
Mul8b/CZjP2Ob0LdpYrNH6l5hvFE89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92
UE68mOyUVXGweJIVDdxqdMoPvNNUl86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/
LUK43YvJh+rhv4nKuF7iHjVjBd9sB6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKN
e6kUhKJ1luB7S27ZkvB3tSTT3P593VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9T
EwIDAQAB
-----END PUBLIC KEY-----`;

// JWT token used in qunit-do-jwt-veri.html ==================================
// tool_jwt.html with one aud
var jwtHS256AUD1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MSwiZXhwIjoyMDgyNzU4Mzk5LCJpYXQiOjE0MzI5MTQ0MzMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciIsImF1ZCI6Imh0dHA6Ly9mb28xLmNvbSJ9.r2mRSoDobgrPg9zDlTEsyQNpua6aGId4UKRYnEo9KRk";

describe("verifyJWT", async () => {
  const KEYHS2AAA = await getHMACKey("hmacSHA256", "616161");

  // alg
  test("alg in HS256", async () => {
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, {alg: ["HS256"]})).toBe(true);
  });
  test("alg not in RS256", async () => {
    expect(async () => {
      await verifyJWT(jwtHS256AUD1, KEYHS2AAA, {alg: ["RS256"]})
    }).toThrow(/acceptable algorithm/);
  });

  // iss
  test("iss accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      iss: ["https://jwt-idp.example.com"],
    };
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)).toBe(true);
  });
  test("iss not accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      iss: ["wrong iss"],
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/iss not accepted/);
  });

  // sub check
  test("sub accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      sub: ["mailto:mike@example.com"],
    };
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)).toBe(true);
  });
  test("sub not accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      sub: ["wrong sub"],
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/sub not accepted/);
  });

  // aud check
  test("aud accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      aud: ["http://foo1.com"],
    };
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)).toBe(true);
  });
  test("aud not accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      aud: ["wrong aud"],
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/aud not accepted/);
  });

  // verifyAt check (1 <= now <= 208275839(=20351231235959Zw))
  test("verifyAt nbf <= at <= exp", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      verifyAt: zulutosec("20201231235959Z"),
    };
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)).toBe(true);
  });
  test("verifyAt at < nbf", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      verifyAt: 0,
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/token not yet/);
  });
  test("verifyAt exp < at", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      verifyAt: zulutosec("20991231235959Z"),
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/token expired/);
  });

  // jti check
  test("jti accept", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      jti: "id123456",
    };
    expect(await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)).toBe(true);
  });
  test("jti accept unmatch", async () => {
    const opt: JWTVerifyOption = {
      alg: ["HS256"],
      jti: "id",
    };
    expect(async () => {await verifyJWT(jwtHS256AUD1, KEYHS2AAA, opt)}).toThrow(/jti not accepted/);
  });

});
/*
pPayload= {
  iss: "https://jwt-idp.example.com",
  sub: "mailto:mike@example.com",
  nbf: 1,
  exp: 2082758399,
  iat: 1432914433,
  jti: "id123456",
  typ: "https://example.com/register",
  aud: "http://foo1.com",
}
 */