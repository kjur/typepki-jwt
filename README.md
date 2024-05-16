typepki-jwt: JWT/JWS sub module for TypePKI library
===================================================

[TOP](https://kjur.github.io/typepki-jwt/) | [github](https://github.com/kjur/typepki-jwt) | [npm](https://www.npmjs.com/package/typepki-jwt) | [TypePKI](https://kjur.github.io/typepki/) 

The 'TypePKI' library is an opensource free TypeScript PKI library which is the successor of the long lived [jsrsasign](https://kjur.github.io/jsrsasign) library.

The 'typepki-jwt' is a JWT(JSON Web Token) and JWS(JSON Web Signatures) sub module for TypePKI library.

## FEATURE
- signing and verifying JWS(JSON Web Signatures)
- Dual CommonJS/ES module package supporting CommonJS(CJS) and ES modules

## Uasge

### signing JWS with private key
This supports asymmetric private key or shared key of CrytoKey object of W3C Crypto API for signing.
It may be useful to generate a key or import a key by using [typepki-webcrypto](https://kjur.github.io/typepki-webcrypto/) module.

```JavaScript
import { importPEM } from "typepki-webcrypto";
const prvkey = await importPEM("-----BEGIN PRIVATE...", "SHA256withRSA");
```

Now you can generate JWS signature.
```JavaScript
import { signJWS } from "typepki-jwt";
const sJWS = await signJWS("RS256", prvkey, "eyJOe...", "eyJpc...");
```
"sJWS" will be a string such like "eyJOe...".

### verifying JWS with public key
Verifying JWS will be similar way. Importing a public key first:
```JavaScript
import { importPEM } from "typepki-webcrypto";
const pubkey = await importPEM("-----BEGIN PUBLIC...", "SHA256withRSA");
```

Verifying JWS signature will be:
```JavaScript
import { verifyJWS } from "typepki-jwt";
const isValid = await verifyJWS(sJWS, pubkey, ["RS256", "RS384", "RS512"]);
```

NOTE: It is strongly recommended to specify the "acceptAlgs" optional argument such like "['RS256', 'RS384']" to prevent algorithm down grade attacks.




