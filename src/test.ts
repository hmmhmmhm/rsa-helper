import * as RSA from './rsa'
(async () => {
    const { privateKey, publicKey } = await RSA.generateKeyPair()
    console.log(`\nprivateKey: ${privateKey}`)
    console.log(`\npublicKey: ${publicKey}`)

    const encrypted = RSA.encrypt('test', publicKey)
    const decrypted = RSA.decrypt(encrypted, privateKey)
    console.log(`\nencrypted: ${encrypted}`)
    console.log(`\ndecrypted: ${decrypted}`)

    const signed = RSA.sign('my public sign', privateKey)
    const extracted = RSA.extract(signed)
    const verified = RSA.verify(signed, 'my public sign', publicKey)

    console.log(`\nsigned: ${signed}`)
    console.log(`\nextracted:`, extracted)
    console.log(`\nverified: ${verified}`)
})()