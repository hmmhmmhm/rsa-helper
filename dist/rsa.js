"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var node_forge_1 = __importDefault(require("node-forge"));
var cbor_1 = __importDefault(require("cbor"));
exports.generateKeyPair = function (options) {
    if (options === void 0) { options = { bits: 2048, workers: 2, e: 0x10001 }; }
    return new Promise(function (resolve) {
        node_forge_1["default"].pki.rsa.generateKeyPair(options, function (err, keypair) {
            resolve({
                publicKey: node_forge_1["default"].pki.publicKeyToPem(keypair.publicKey),
                privateKey: node_forge_1["default"].pki.privateKeyToPem(keypair.privateKey)
            });
        });
    });
};
exports.encrypt = function (message, publicKey, format) {
    if (format === void 0) { format = 'base64'; }
    return Buffer.from(node_forge_1["default"].pki.publicKeyFromPem(publicKey).encrypt(node_forge_1["default"].util.encodeUtf8(message))).toString(format);
};
exports.decrypt = function (encrypted, privateKey, formmat) {
    if (formmat === void 0) { formmat = 'base64'; }
    return node_forge_1["default"].pki.privateKeyFromPem(privateKey).decrypt(Buffer.from(encrypted, formmat).toString());
};
exports._sign = function (message, privateKey, format) {
    if (format === void 0) { format = 'base64'; }
    var md = node_forge_1["default"].md.sha1.create();
    md.update(node_forge_1["default"].util.encodeUtf8(message), 'utf8');
    return Buffer.from(node_forge_1["default"].pki.privateKeyFromPem(privateKey).sign(md)).toString(format);
};
exports._verify = function (signature, message, publicKey, format) {
    if (format === void 0) { format = 'base64'; }
    var md = node_forge_1["default"].md.sha1.create();
    md.update(node_forge_1["default"].util.encodeUtf8(message), 'utf8');
    return node_forge_1["default"].pki.publicKeyFromPem(publicKey).verify(md.digest().bytes(), Buffer.from(signature, format).toString());
};
exports.sign = function (message, privateKey, format) {
    if (format === void 0) { format = 'base64'; }
    var md = node_forge_1["default"].md.sha1.create();
    md.update(node_forge_1["default"].util.encodeUtf8(message), 'utf8');
    var signedObject = {
        sign: exports._sign(message, privateKey, format),
        message: message
    };
    return cbor_1["default"].encode(signedObject).toString(format);
};
exports.extract = function (signature, format) {
    if (format === void 0) { format = 'base64'; }
    var signedObject = cbor_1["default"].decode(Buffer.from(signature, format));
    if (typeof signedObject.sign != 'string')
        return undefined;
    if (typeof signedObject.message != 'string')
        return undefined;
    return signedObject;
};
exports.verify = function (signature, message, publicKey, format) {
    if (format === void 0) { format = 'base64'; }
    var signedObject = cbor_1["default"].decode(Buffer.from(signature, format));
    return exports._verify(signedObject.sign, message, publicKey, format);
};
