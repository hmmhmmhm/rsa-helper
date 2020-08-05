import forge from 'node-forge';
declare type encodingType = "ascii" | "utf8" | "utf-8" | "utf16le" | "ucs2" | "ucs-2" | "base64" | "latin1" | "binary" | "hex" | undefined;
export declare const generateKeyPair: (options?: forge.pki.rsa.GenerateKeyPairOptions) => Promise<{
    publicKey: string;
    privateKey: string;
}>;
export declare const encrypt: (message: string, publicKey: string, format?: encodingType) => string;
export declare const decrypt: (encrypted: string, privateKey: string, formmat?: encodingType) => string;
export declare const _sign: (message: string, privateKey: string, format?: encodingType) => string;
export declare const _verify: (signature: string, message: string, publicKey: string, format?: encodingType) => boolean;
export declare const sign: (message: string, privateKey: string, format?: encodingType) => string;
export declare const extract: (signature: string, format?: encodingType) => {
    sign: string;
    message: string;
} | undefined;
export declare const verify: (signature: string, message: string, publicKey: string, format?: encodingType) => boolean;
export {};
