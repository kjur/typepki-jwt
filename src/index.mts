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
