const subtle =
    typeof crypto !== "undefined" ? crypto.subtle : await import("node:crypto").then(crypto => crypto.subtle);

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

function arrayToBase64String(array: ArrayBuffer) {
    return typeof Buffer !== "undefined"
        ? Buffer.from(array).toString("base64")
        : btoa(String.fromCharCode(...new Uint8Array(array)));
}

function base64StringToArray(str: string): ArrayBuffer {
    return typeof Buffer !== "undefined"
        ? Buffer.from(str, "base64")
        : Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
}

async function privateKeyToString(key: CryptoKey) {
    return arrayToBase64String(await subtle.exportKey("pkcs8", key));
}

async function publicKeyToString(key: CryptoKey) {
    return arrayToBase64String(await subtle.exportKey("spki", key));
}

async function stringToPrivateKey(key: string) {
    return subtle.importKey(
        "pkcs8",
        base64StringToArray(key),
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
        base64StringToArray(key),
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
        new TextEncoder().encode(JSON.stringify(data))
    );

    return arrayToBase64String(signature);
}

export async function verify(data: any, publicKey: string, signature: string): Promise<boolean> {
    return subtle.verify(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        await stringToPublicKey(publicKey),
        base64StringToArray(signature),
        new TextEncoder().encode(JSON.stringify(data))
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
