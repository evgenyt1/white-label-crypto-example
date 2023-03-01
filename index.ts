import { generateKeyValuePair, sign, verify } from "./crypto";

const whiteLabelKeys = await generateKeyValuePair();
const WHITE_LABEL_PRIVATE_KEY = whiteLabelKeys.privateKey;
const WHITE_LABEL_PUBLIC_KEY = whiteLabelKeys.publicKey;

// on white-label server
async function generateScopeSecret(scope: string) {
    // scope should only contain letters, numbers, and dashes
    if (!/^[a-zA-Z0-9-]+$/.test(scope)) throw new Error("Invalid scope");
    const pair = await generateKeyValuePair();
    const publicKeyScopeSignature = await sign([scope, pair.publicKey], WHITE_LABEL_PRIVATE_KEY);
    return [scope, pair.privateKey, pair.publicKey, publicKeyScopeSignature].join(":");
}

// on Grip side
async function signWithScopeSecret(data: any, scopeKey: string) {
    const [scope, privateKey, publicKey, publicKeySignature] = scopeKey.split(":");
    const signature = await sign(data, privateKey);
    return [signature, scope, publicKey, publicKeySignature].join(":");
}

// on designer side + on "send-data", etc. side
async function getVerifiedScopeForData(data: any, signature: string): Promise<string> {
    const sigCombined = signature;
    const [dataSignature, scope, publicKey, publicKeyScopeSignature] = sigCombined.split(":");
    // check data signature
    if (!(await verify(data, publicKey, dataSignature))) throw new Error("Invalid signature");
    // check public key + scope signature
    if (!(await verify([scope, publicKey], WHITE_LABEL_PUBLIC_KEY, publicKeyScopeSignature)))
        throw new Error("Invalid public key and scope signature");

    return scope;
}

const gripSecret = await generateScopeSecret("grip");
console.log(gripSecret);
const signature = await signWithScopeSecret({ expo: 22 }, gripSecret);
console.log(signature);
const verifiedScope = await getVerifiedScopeForData({ expo: 22 }, signature);
console.log("verified scope:", verifiedScope);
