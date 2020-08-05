
import forge from 'node-forge'
import cbor from 'cbor'
type encodingType = "ascii" | "utf8" | "utf-8" | "utf16le" | "ucs2" | "ucs-2" | "base64" | "latin1" | "binary" | "hex" | undefined


export const generateKeyPair = (
    options: forge.pki.rsa.GenerateKeyPairOptions = { bits: 2048, workers: 2, e: 0x10001 }
): Promise<{
    publicKey: string
    privateKey: string
}> => {
    return new Promise((resolve) => {
        forge.pki.rsa.generateKeyPair(options, (err, keypair) => {
            resolve({
                publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
                privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
            })
        })
    })
}

export const encrypt = (
    message: string,
    publicKey: string,
    format: encodingType = 'base64'
) => {
    return Buffer.from(forge.pki.publicKeyFromPem(publicKey).encrypt(forge.util.encodeUtf8(message))).toString(format)
}

export const decrypt = (
    encrypted: string,
    privateKey: string,
    formmat: encodingType = 'base64'
) => {
    return forge.pki.privateKeyFromPem(privateKey).decrypt(Buffer.from(encrypted, formmat).toString())
}

export const _sign = (
    message: string,
    privateKey: string,
    format: encodingType = 'base64'
) => {
    const md = forge.md.sha1.create()
    md.update(forge.util.encodeUtf8(message), 'utf8')
    return Buffer.from(forge.pki.privateKeyFromPem(privateKey).sign(md)).toString(format)
}

export const _verify = (
    signature: string,
    message: string,
    publicKey: string,
    format: encodingType = 'base64'
) => {
    const md = forge.md.sha1.create()
    md.update(forge.util.encodeUtf8(message), 'utf8')
    return forge.pki.publicKeyFromPem(publicKey).verify(md.digest().bytes(), Buffer.from(signature, format).toString())
}

export const sign = (
    message: string,
    privateKey: string,
    format: encodingType = 'base64'
) => {
    const md = forge.md.sha1.create()
    md.update(forge.util.encodeUtf8(message), 'utf8')
    const signedObject = {
        sign: _sign(message, privateKey, format),
        message,
    }
    return cbor.encode(signedObject).toString(format)
}

export const extract = (
    signature: string,
    format: encodingType = 'base64'
): undefined | {
    sign: string
    message: string
} => {
    const signedObject = cbor.decode(
        Buffer.from(signature, format)
    )

    if (typeof signedObject.sign != 'string') return undefined
    if (typeof signedObject.message != 'string') return undefined
    return signedObject
}

export const verify = (
    signature: string,
    message: string,
    publicKey: string,
    format: encodingType = 'base64'
) => {
    const signedObject = cbor.decode(
        Buffer.from(signature, format)
    )
    return _verify(signedObject.sign, message, publicKey, format)
}

(async () => {
    const { privateKey, publicKey } = await generateKeyPair()
    console.log(`\nprivateKey: ${privateKey}`)
    console.log(`\npublicKey: ${publicKey}`)

    const encrypted = encrypt('test', publicKey)
    const decrypted = decrypt(encrypted, privateKey)
    console.log(`\nencrypted: ${encrypted}`)
    console.log(`\ndecrypted: ${decrypted}`)

    const signed = sign('my public sign', privateKey)
    const extracted = extract(signed)
    const verified = verify(signed, 'my public sign', publicKey)

    console.log(`\nsigned: ${signed}`)
    console.log(`\nextracted:`, extracted)
    console.log(`\nverified: ${verified}`)
})()