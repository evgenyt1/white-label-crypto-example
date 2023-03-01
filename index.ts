import { generateKeyValuePair, sign, verify } from "./crypto";

const whiteLabelKeys = await generateKeyValuePair();
const WHITE_LABEL_PRIVATE_KEY = whiteLabelKeys.privateKey;
const WHITE_LABEL_PUBLIC_KEY = whiteLabelKeys.publicKey;

function combine(...keys: string[]) {
    return keys.join(":");
}

// on white-label server
async function generateScopeKey(scope: string) {
    const pair = await generateKeyValuePair();
    const data = combine(scope, pair.publicKey);
    const signature = await sign(data, WHITE_LABEL_PRIVATE_KEY);
    return combine(scope, pair.privateKey, pair.publicKey, signature);
}

// on Grip side
async function signWithScopeKey(data: any, scopeKey: string) {
    const [scope, privateKey, publicKey, publicKeySignature] = scopeKey.split(":");
    const signature = await sign(data, privateKey);
    return combine(scope, signature, publicKey, publicKeySignature);
}

// on designer side
async function getVerifiedScopeForData(data: any, signature: string): Promise<string> {
    const sigCombined = signature;
    const [scope, dataSignature, publicKey, publicKeySignature] = sigCombined.split(":");
    if (!(await verify(data, publicKey, dataSignature))) throw new Error("Invalid signature");
    if (!(await verify(combine(scope, publicKey), WHITE_LABEL_PUBLIC_KEY, publicKeySignature)))
        throw new Error("Invalid public key and scope signature");

    return scope;
}

const gripSecret = await generateScopeKey("grip");
console.log(gripSecret);
const signature = await signWithScopeKey({ expo: 22 }, gripSecret);
console.log(signature);
const verifiedScope = await getVerifiedScopeForData({ expo: 22 }, signature);
console.log("verified scope:", verifiedScope);
