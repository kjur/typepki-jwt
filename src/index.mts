import {
  b64utohex,
  b64utoutf8,
  hextob64u,
  isBase64URL,
  utf8tohex,
} from "typepki-strconv";
import {
  signHMACHex,
  signHex,
  verifyHMACHex,
  verifyHex,
} from "typepki-webcrypto";

/**
 * sign JWS (JSON Web Signature)
 * @param alg - JWS signature algorithm
 * @param key - private key object
 * @param header - JWS header
 * @param payload - JWS payload
 * @return JWS signature string
 * @see https://www.rfc-editor.org/rfc/rfc7515.html
 * @example
 * await signJWS("RS256", prvkey, "eyJOe..", "eyJpc...") -> "eyJOe..."
 */
export async function signJWS(
  alg: string,
  key: CryptoKey,
  header: string,
  payload: string,
): Promise<string> {
  const algMatch = alg.match(/^(HS|RS|PS|ES)(256|384|512)$/);
  if (algMatch == null) {
    throw new Error(`algorithm not supported: ${alg}`);
  }

  const sHeader = header;
  const sPayload = payload;

  if (!isBase64URL(sHeader)) {
    throw new Error("header must be Base64URL encoded");
  }
  if (!isBase64URL(sPayload)) {
    throw new Error("payload must be Base64URL encoded");
  }

  const sTBS = `${sHeader}.${sPayload}`;
  const hTBS = utf8tohex(sTBS);

  const sigalg = algjwstosig(algMatch[1], algMatch[2]);
  let hSig: string;
  if (algMatch[1] === "HS") {
    hSig = await signHMACHex(sigalg, key, hTBS);
  } else if (algMatch[1] === "ES") {
    //hSig = await signHex(sigalg, key, hTBS, algjwstocurve(alg));
    hSig = await signHex(sigalg, key, hTBS);
  } else {
    hSig = await signHex(sigalg, key, hTBS);
  }
  return `${sTBS}.${hextob64u(hSig)}`;
}

/**
 * verifiy JWS signature
 * @param sJWS - JWS signature string
 * @param key - public key object to verify
 * @param acceptAlgs - acceptable JWS signature algorithm to avoid downgrade attacks (OPTION)
 * @return true if JWS signature is valid
 * @see https://www.rfc-editor.org/rfc/rfc7515.html
 * @example
 * await verifyJWS("eJYOe...", pubkey) -> true/false
 * await verifyJWS("eJYOe...", pubkey, ["RS512", "PS512"]) -> true/false
 */
export async function verifyJWS(
  sJWS: string,
  key: CryptoKey,
  acceptAlgs?: Array<string>,
): Promise<boolean> {
  const [sHead, sPayload, sSig] = sJWS.split(".");
  const pHead: Record<string, string> = JSON.parse(b64utoutf8(sHead));
  const alg: string = pHead.alg;
  const algMatch = alg.match(/^(HS|RS|PS|ES)(256|384|512)$/);

  if (algMatch == null) {
    throw new Error(`algorithm not supported: ${alg}`);
  }

  if (acceptAlgs !== undefined && !acceptAlgs.includes(alg)) {
    throw new Error(`header algorithm not accepted: ${alg}`);
  }

  const sigalg = algjwstosig(algMatch[1], algMatch[2]);
  const hData = utf8tohex(`${sHead}.${sPayload}`);
  const hSig = b64utohex(sSig);
  if (algMatch[1] === "ES") {
    return await verifyHex(sigalg, key, hSig, hData, algjwstocurve(alg));
  }
  if (algMatch[1] === "HS") {
    return await verifyHMACHex(sigalg, key, hSig, hData);
  }
  return await verifyHex(sigalg, key, hSig, hData);
}

function algjwstocurve(alg: string): string {
  if (alg === "ES256") return "P-256";
  if (alg === "ES384") return "P-384";
  if (alg === "ES512") return "P-521";
  throw new Error(`alg not supported: ${alg}`);
}

function algjwstosig(shortAlg: string, shortHashAlg: string): string {
  let alg1: string;
  let alg2: string;
  if (shortHashAlg === "256") {
    alg1 = "SHA256";
  } else if (shortHashAlg === "384") {
    alg1 = "SHA384";
  } else if (shortHashAlg === "512") {
    alg1 = "SHA512";
  } else {
    throw new Error(`shortHashAlg not supported: ${shortHashAlg}`);
  }

  if (shortAlg === "HS") {
    alg2 = "hmac";
  } else if (shortAlg === "RS") {
    alg2 = "withRSA";
  } else if (shortAlg === "PS") {
    alg2 = "withRSAandMGF1";
  } else if (shortAlg === "ES") {
    alg2 = "withECDSA";
  } else {
    throw new Error(`shortAlg not supported: ${shortAlg}`);
  }

  if (shortAlg === "HS") return `${alg2}${alg1}`;
  return `${alg1}${alg2}`;
}

const ALGJWSTOSIG: Record<string, string> = {
  HS256: "hmacSHA256",
  HS384: "hmacSHA384",
  HS512: "hmacSHA512",
  RS256: "SHA256withRSA",
  RS384: "SHA384withRSA",
  RS512: "SHA512withRSA",
  PS256: "SHA256withRSAandMGF1",
  PS384: "SHA384withRSAandMGF1",
  PS512: "SHA512withRSAandMGF1",
  ES256: "SHA256withECDSA",
  ES384: "SHA384withECDSA",
  ES512: "SHA512withECDSA",
};

/*
 *   alg: ['RS256', 'RS512', 'PS256', 'PS512'],
 *   iss: ['http://foo.com'],
 *   sub: ['mailto:john@foo.com', 'mailto:alice@foo.com'],
 *   verifyAt: KJUR.jws.IntDate.get('20150520235959Z'),
 *   aud: ['http://foo.com'], // aud: 'http://foo.com' is fine too.
 *   jti: 'id123456',
 *   gracePeriod: 1 * 60 * 60 // accept 1 hour slow or fast
 */
/**
 * verify parameters for {@link verifyJWT}
 */
export interface JWTVerifyOption {
  /** acceptable JWS algorithm */
  alg: string[];
  /** acceptable JWT issuer claim */
  iss?: string[];
  /** acceptable JWT subject claim */
  sub?: string[];
  /** acceptable JWT audience claim */
  aud?: string[];
  /** time in second from Unix origin to verify */
  verifyAt?: number;
  /** acceptable JWT ID claim */
  jti?: string;
  /** acceptable time difference seconds to relax nbf and exp */
  gracePeriod?: number;
}

/**
 * verify JWT (JSON Web Token)
 * @param sJWT - JWT string to verify
 * @param key - key object to verify
 * @param verifyOption - verify parameters
 * @throws Error if JWT can't be verified
 * @return true if successfully verified
 * @see https://www.rfc-editor.org/rfc/rfc7519
 * @see verifyJWS
 * @example
 * const key = await getHMACKey("hmacSHA256", "12ab...");
 * await verifyJWT("eyJhb...", key, {
 *   alg: ["HS256", "HS384"],
 *   iss: ["https://jwt-idp.example.com"],
 *   sub: ["mailto:mike@example.com", "mailto:joe@example.com"],
 *   aud: ["http://foo1.com"],
 *   jti: "id123456",
 * }) -> true
 */
export async function verifyJWT(sJWT: string, key: CryptoKey, verifyOption: JWTVerifyOption): Promise<boolean> {
  const [sHead, sPayload, sSig] = sJWT.split(".");
  let pHead: Record<string, string>;
  let pPayload: Record<string, number | string | string[]>;
  //console.log("sHead=", sHead);

  // parse header
  try {
    pHead = JSON.parse(b64utoutf8(sHead));
  } catch (ex) {
    throw new Error(`malformed header: ${sHead}`);
  }

  // algorithm check in header
  try {
    if (!verifyOption.alg.includes(pHead.alg)) throw Error("alg");
  } catch (ex) {
    throw new Error(`acceptable algorithm unmatch: ${ex}`);
  }

  // typ check in header
  if ((pHead.typ as string) !== "JWT") {
    throw new Error(`typ in header not JWT`);
  }

  // parse payload
  try {
    pPayload = JSON.parse(b64utoutf8(sPayload));
  } catch (ex) {
    throw new Error(`malformed payload: ${sPayload}`);
  }

  // iss check
  if (verifyOption.iss !== undefined) {
    const acceptISS: string[] = verifyOption.iss;
    if (!acceptISS.includes(pPayload.iss as string)) {
      throw new Error(`iss not accepted: ${pPayload.iss} in ${verifyOption.iss}`);
    }
  }

  // sub check
  if (verifyOption.sub !== undefined) {
    const acceptSUB: string[] = verifyOption.sub;
    if (!acceptSUB.includes(pPayload.sub as string)) {
      throw new Error(`sub not accepted: ${pPayload.sub} in ${verifyOption.sub}`);
    }
  }

  // aud check
  if (verifyOption.aud !== undefined) {
    const acceptAUD: string[] = verifyOption.aud;
    if (!acceptAUD.includes(pPayload.aud as string)) {
      throw new Error(`aud not accepted: ${pPayload.aud} in ${verifyOption.aud}`);
    }
  }

  // exp check (now <= exp)
  const verifyAt: number = (verifyOption.verifyAt !== undefined) ? verifyOption.verifyAt : getnow();
  const gracePeriod: number = (verifyOption.gracePeriod !== undefined) ? verifyOption.gracePeriod : 0;
  if (pPayload.exp !== undefined) {
    const acceptEXP: number = (pPayload.exp as number) + gracePeriod;
    if (verifyAt > acceptEXP) {
      throw new Error(`token expired: v=${verifyAt}, exp=${acceptEXP}`);
    }
  }

  // nbf check (nbf <= now)
  if (pPayload.nbf !== undefined) {
    const acceptNBF: number = (pPayload.nbf as number) - gracePeriod;
    if (verifyAt < acceptNBF) {
      throw new Error(`token not yet available: v=${verifyAt}, nbf=${acceptNBF}`);
    }
  }

  // jti check
  if (verifyOption.jti !== undefined) {
    const acceptJTI: string = verifyOption.jti;
    if (pPayload.jti !== undefined && pPayload.jti !== acceptJTI) {
      throw new Error(`jti not accepted: jti=${pPayload.jti}, accept=${acceptJTI}`);
    }
  }

  // verify JWS signature
  try {
    const result = await verifyJWS(sJWT, key, verifyOption.alg);
    return result;
  } catch (ex) {
    throw new Error(`invalid signature: ${ex}`);
  }

  return true;
}

/**
 * get NumericDate of current time
 * @return NumericDate value
 * @description
 * This function returns a current time number of seconds 
 * from Unix origin time (i.e. 1970-01-01T00:00:00Z UTC).
 * @example
 * getnow() -> 1716204320
 */
export function getnow() {
  return ~~(Date.now() / 1000);
}

