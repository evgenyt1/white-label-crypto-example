import { subtle } from "node:crypto";

export async function generateKeyValuePair() {
    const pair = await subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
    );

    return {
        privateKey: await privateKeyToString(pair.privateKey),
        publicKey: await publicKeyToString(pair.publicKey),
    };
}

async function privateKeyToString(key: CryptoKey) {
    return Buffer.from(await subtle.exportKey("pkcs8", key)).toString("base64");
}

async function publicKeyToString(key: CryptoKey) {
    return Buffer.from(await subtle.exportKey("spki", key)).toString("base64");
}

async function stringToPrivateKey(key: string) {
    return subtle.importKey(
        "pkcs8",
        Buffer.from(key, "base64"),
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        true,
        ["sign"]
    );
}

async function stringToPublicKey(key: string) {
    return subtle.importKey(
        "spki",
        Buffer.from(key, "base64"),
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        true,
        ["verify"]
    );
}

export async function sign(data: any, privateKey: string): Promise<string> {
    const signature = await subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        await stringToPrivateKey(privateKey),
        Buffer.from(JSON.stringify(data))
    );

    return Buffer.from(signature).toString("base64");
}

export async function verify(data: any, publicKey: string, signature: string): Promise<boolean> {
    return subtle.verify(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        await stringToPublicKey(publicKey),
        Buffer.from(signature, "base64"),
        Buffer.from(JSON.stringify(data))
    );
}

// export async function getPublicKeyFromPrivateKey(privateKey: string) {
//     const pk = await stringToPrivateKey(privateKey);
//     const jwk = await subtle.exportKey("jwk", pk);
//     // remove private data from JWK
//     delete jwk.d;
//     delete jwk.dp;
//     delete jwk.dq;
//     delete jwk.q;
//     delete jwk.qi;
//     jwk.key_ops = ["verify"];

//     const publicKey = await subtle.importKey(
//         "jwk",
//         jwk,
//         {
//             name: "RSA-PSS",
//             hash: "SHA-256",
//         },
//         true,
//         ["verify"]
//     );

//     return await publicKeyToString(publicKey);
// }

// TEST
// const pair = await generateKeyValuePair();
// console.log(pair);
// const signature = await sign("abc", pair.privateKey);
// console.log("Signature valid: ", await verify("abc", pair.publicKey, signature));
// console.log((await getPublicKeyFromPrivateKey(pair.privateKey)) === pair.publicKey);
