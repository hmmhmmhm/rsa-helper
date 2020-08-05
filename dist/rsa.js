"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
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
(function () { return __awaiter(void 0, void 0, void 0, function () {
    var _a, privateKey, publicKey, encrypted, decrypted, signed, extracted, verified;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, exports.generateKeyPair()];
            case 1:
                _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                console.log("\nprivateKey: " + privateKey);
                console.log("\npublicKey: " + publicKey);
                encrypted = exports.encrypt('test', publicKey);
                decrypted = exports.decrypt(encrypted, privateKey);
                console.log("\nencrypted: " + encrypted);
                console.log("\ndecrypted: " + decrypted);
                signed = exports.sign('my public sign', privateKey);
                extracted = exports.extract(signed);
                verified = exports.verify(signed, 'my public sign', publicKey);
                console.log("\nsigned: " + signed);
                console.log("\nextracted:", extracted);
                console.log("\nverified: " + verified);
                return [2 /*return*/];
        }
    });
}); })();
