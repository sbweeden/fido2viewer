// mykeyutil.js

/**
 * Uses the SubtleCrypto library to implement a range of utility functions suitable for FIDO operations.
 * Useful examples found at: https://gist.github.com/pedrouid/b4056fd1f754918ddae86b32cf7d803e
 */

(function(global) {

// values from IANA COSE Algorithms registry
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// if you want to force the client to only support one or a subset of credential algorithms
// change this to the appropriate value
const allAlgorithms = [ -7, -8, -35, -36, -37, -38, -39, -48, -49, -50, -257, -258, -259, -65535 ];

const availableAlgorithms = [];

/**
 * Extracts the bytes from an array beginning at index start, and continuing until
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to
 * parse till the end of the array.
 */
function bytesFromArray(o, start, end) {
	// o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
	let len = o.length;
	if (len == null) {
		len = Object.keys(o).length;
	}

	let result = [];
	for (let i = start; (end == -1 || i < end) && i < len; i++) {
		result.push(o[i]);
	}
	return result;
}

/*
* This array contains a set of objects - one for each of the key algorithms supported by
* these functions. Each object contains the following properties:
*  name: the name of the signing algorithm
*  algId: the algorithm id from the IANA registry (https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
*  coseKeyType: the COSE key type
*  coseKeyAlg: the COSE algorithm id
* createParams: the parameters to use when creating a new key (or importing a key) used by this algorithm
* signParams: the parameters to use when signing a message with this key type
* verifyParams: the parameters to use when verifying a message with this key type
* 
* The createParams and signParams properties are used when creating a new key of this type, or importing a key of this type.
* The verifyParams property is used when verifying a message with this key type.
* 
* The createParams property is an object that is passed to the Web Cryptography API's subtle.generateKey() and subtle.importKey() methods.
* The signParams property is an algorithm identifier that is passed to the Web Cryptography API's subtle.sign() method.
* The verifyParams property is an algorithm identifier that is passed to the Web Cryptography API's subtle.verify() method.
* 
*/
const SUPPORTED_ALGS = [ 
    // RS256, -257
    {
        name: 'RS256',
        algId: -257,
        coseKeyType: 3,
        coseKeyAlg: -257,
        createParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: 'RSASSA-PKCS1-v1_5',
        verifyParams: 'RSASSA-PKCS1-v1_5',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // RS384, -258
    {
        name: 'RS384',
        algId: -258,
        coseKeyType: 3,
        coseKeyAlg: -258,
        createParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-384',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: 'RSASSA-PKCS1-v1_5',
        verifyParams: 'RSASSA-PKCS1-v1_5',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // RS512, -259
    {
        name: 'RS512',
        algId: -259,
        coseKeyType: 3,
        coseKeyAlg: -259,
        createParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-512',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: 'RSASSA-PKCS1-v1_5',
        verifyParams: 'RSASSA-PKCS1-v1_5',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // RS1, -65535
    {
        name: 'RS1',
        algId: -65535,
        coseKeyType: 3,
        coseKeyAlg: -65535,
        createParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-1',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: 'RSASSA-PKCS1-v1_5',
        verifyParams: 'RSASSA-PKCS1-v1_5',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // ES256, -7
    {
        name: 'ES256',
        algId: -7,
        coseKeyType: 2,
        coseKeyAlg: -7,
        createParams: {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        signParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        verifyParams: {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        getPublicKeyCOSE : function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": 1, // crv
                        "-2": b64toBA(b64utob64(jwkPK.x)), // xCoordinate
                        "-3": b64toBA(b64utob64(jwkPK.y)) // yCoordinate
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "kty": "EC",
                    "crv": this.createParams.namedCurve,
                    "key_ops": [
                        "verify"
                    ],
                    "ext": true,
                    "x": hextob64u(BAtohex(coseKey["-2"])),
                    "y": hextob64u(BAtohex(coseKey["-3"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // Ed25519, -8
    {
        name: 'Ed25519',
        algId: -8,
        coseKeyType: 1,
        coseKeyAlg: -8,
        createParams: 'Ed25519',
        signParams: 'Ed25519',
        verifyParams: 'Ed25519',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": 6, // crv
                        "-2": b64toBA(b64utob64(jwkPK.x))// xCoordinate
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                "alg": this.name,
                "crv": this.name,
                "ext": true,
                "key_ops": [
                    "verify"
                ],
                "kty": "OKP",
                "x": hextob64u(BAtohex(coseKey["-2"]))
            };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // ES384, -35
    {
        name: 'ES384',
        algId: -35,
        coseKeyType: 2,
        coseKeyAlg: -35,
        createParams: {
            name: 'ECDSA',
            namedCurve: 'P-384'
        },
        signParams: {
            name: 'ECDSA',
            hash: 'SHA-384'
        },
        verifyParams: {
            name: 'ECDSA',
            hash: 'SHA-384'
        },
        getPublicKeyCOSE : function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": 2, // crv
                        "-2": b64toBA(b64utob64(jwkPK.x)), // xCoordinate
                        "-3": b64toBA(b64utob64(jwkPK.y)) // yCoordinate
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "kty": "EC",
                    "crv": this.createParams.namedCurve,
                    "key_ops": [
                        "verify"
                    ],
                    "ext": true,
                    "x": hextob64u(BAtohex(coseKey["-2"])),
                    "y": hextob64u(BAtohex(coseKey["-3"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // ES512, -36
    {
        name: 'ES512',
        algId: -36,
        coseKeyType: 2,
        coseKeyAlg: -36,
        createParams: {
            name: 'ECDSA',
            namedCurve: 'P-521'
        },
        signParams: {
            name: 'ECDSA',
            hash: 'SHA-512'
        },
        verifyParams: {
            name: 'ECDSA',
            hash: 'SHA-512'
        },
        getPublicKeyCOSE : function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": 3, // crv
                        "-2": b64toBA(b64utob64(jwkPK.x)), // xCoordinate
                        "-3": b64toBA(b64utob64(jwkPK.y)) // yCoordinate
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "kty": "EC",
                    "crv": this.createParams.namedCurve,
                    "key_ops": [
                        "verify"
                    ],
                    "ext": true,
                    "x": hextob64u(BAtohex(coseKey["-2"])),
                    "y": hextob64u(BAtohex(coseKey["-3"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }, 
    // PS256, -37
    {
        name: 'PS256',
        algId: -37,
        coseKeyType: 3,
        coseKeyAlg: -37,
        createParams: {
            name: 'RSA-PSS',
            hash: 'SHA-256',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: {
            name: 'RSA-PSS',
            saltLength: 32 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        verifyParams: {
            name: 'RSA-PSS',
            saltLength: 32 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // PS384, -38
    {
        name: 'PS384',
        algId: -38,
        coseKeyType: 3,
        coseKeyAlg: -38,
        createParams: {
            name: 'RSA-PSS',
            hash: 'SHA-384',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: {
            name: 'RSA-PSS',
            saltLength: 48 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        verifyParams: {
            name: 'RSA-PSS',
            saltLength: 48 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // PS512, -39
    {
        name: 'PS512',
        algId: -39,
        coseKeyType: 3,
        coseKeyAlg: -39,
        createParams: {
            name: 'RSA-PSS',
            hash: 'SHA-512',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1])
        },
        signParams: {
            name: 'RSA-PSS',
            saltLength: 64 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        verifyParams: {
            name: 'RSA-PSS',
            saltLength: 64 // from https://www.rfc-editor.org/rfc/rfc8230.html#section-2 
        },
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.n)), // n
                        "-2": [1,0,1], // exponent 65537
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                    "alg": this.name,
                    "e": hextob64u(BAtohex(coseKey["-2"])),
                    "ext": true,
                    "key_ops": [
                        "verify"
                    ],
                    "kty": "RSA",
                    "n": hextob64u(BAtohex(coseKey["-1"]))
                };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // ML-DSA-44, -48
    {
        name: 'ML-DSA-44',
        algId: -48,
        coseKeyType: 7,
        coseKeyAlg: -48,
        createParams: 'ML-DSA-44',
        signParams: 'ML-DSA-44',
        verifyParams: 'ML-DSA-44',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.pub)) // pub
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                "key_ops": [
                    "verify"
                ],
                "ext": true,
                "kty": "AKP",
                "alg": this.name,
                "pub": hextob64u(BAtohex(coseKey["-1"]))
            };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // ML-DSA-65, -49
    {
        name: 'ML-DSA-65',
        algId: -49,
        coseKeyType: 7,
        coseKeyAlg: -49,
        createParams: 'ML-DSA-65',
        signParams: 'ML-DSA-65',
        verifyParams: 'ML-DSA-65',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.pub)) // pub
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                "key_ops": [
                    "verify"
                ],
                "ext": true,
                "kty": "AKP",
                "alg": this.name,
                "pub": hextob64u(BAtohex(coseKey["-1"]))
            };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    },
    // ML-DSA-87, -50
    {
        name: 'ML-DSA-87',
        algId: -50,
        coseKeyType: 7,
        coseKeyAlg: -50,
        createParams: 'ML-DSA-87',
        signParams: 'ML-DSA-87',
        verifyParams: 'ML-DSA-87',
        getPublicKeyCOSE: function(kp) {
            return crypto.subtle.exportKey('jwk', (kp instanceof CryptoKey ? kp : kp.publicKey))
            .then((jwkPK) => {
                return {
                        "1": this.coseKeyType, // kty
                        "3": this.coseKeyAlg, // alg
                        "-1": b64toBA(b64utob64(jwkPK.pub)) // pub
                };
            });
        },
        getPublicKeyFromCOSE: function(coseKey) {
            let jwkPk = {
                "key_ops": [
                    "verify"
                ],
                "ext": true,
                "kty": "AKP",
                "alg": this.name,
                "pub": hextob64u(BAtohex(coseKey["-1"]))
            };
            return crypto.subtle.importKey(
                "jwk",
                jwkPk,
                this.createParams,
                true,
                ["verify"]
            );
        }
    }
];

/**
 * The init function should be called once to initialize the availableAlgorithms array.
 * This is done by attempting to generate a keypair for each algorithm listed in allAlgorithms.
 * If an algorithm is supported by the SubtleCrypto API implementation, 
 * it will be added to the availableAlgorithms array.
 * 
 * @returns a Promise that should be resolved before calling any other mykeyutil functions.
 */
function init() {
    let allPromises = [];
    // discovery of available key types from subset of key types
    allAlgorithms.forEach((k) => {
            allPromises.push(
                generateKeypair(k)
                .then(kp => {
                    if (availableAlgorithms.indexOf(k) < 0) {
                        availableAlgorithms.push(k);
                    }                    
                }).catch((e) => {
                }));
            });
    return Promise.all(allPromises).then(() => {
        console.log("The supported algorithms are: ", availableAlgorithms.sort());
        console.log("The unavailable algorithms are: ", allAlgorithms.filter(alg => availableAlgorithms.indexOf(alg) < 0).sort());
    });
}


/**
 * Determine if a particular algorithm ID is supported. Must be called after init()
 * @param algId 
 * @returns true of the algorithm is supported, false otherwise
 */
function supportsPubKeyCredParam(algId) {
    return availableAlgorithms.indexOf(algId) >= 0;
}

/**
 * Attempts to generate a keypair for the specified algorithm ID.
 * @param algId 
 * @returns a Promise that resolves to a keypair object containing the algorithm id, and public and private keys.
 * Will be rejected if the algorithm is not supported.
 */
function generateKeypair(algId) {
    return new Promise((resolve, reject) => {
        let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
        if (supportedAlgInfo) {
            crypto.subtle.generateKey(supportedAlgInfo.createParams, true, ['sign', 'verify'])
            .then(kp => {
                resolve({
                    algId: algId,
                    publicKey: kp.publicKey,
                    privateKey: kp.privateKey
                });
            }).catch((e) => {
                reject(e);
            });
        } else {
            reject(new Error("Unsupported algorithm: " + algId));
        }
    });
}

/**
 * Returns a Promise which will extract the private key as hex string from a private CryptoKey or keypair previously generated with generateKeypair
 * @param kp - can be the keypair, or a private CryptoKey
 * @returns a Promise resolving to the hex string of the private key bytes.
 */
function getPrivateKeyHex(kp) {
    let privKey = (kp instanceof CryptoKey) ? kp : kp.privateKey;
    return crypto.subtle.exportKey('pkcs8', privKey)
    .then((privKeyAB) => {
        return BAtohex(bytesFromArray(new Uint8Array(privKeyAB), 0, -1));
    });
}

/**
 * Returns a Promise which will extract the public key as hex string from a public CryptoKey or keypair previously generated with generateKeypair
 * @param kp - can be the keypair, or a private CryptoKey
 * @returns a Promise resolving to the hex string of the public key bytes.
 */
function getPublicKeyHex(kp) {
    let pubKey = (kp instanceof CryptoKey) ? kp : kp.publicKey;
    return crypto.subtle.exportKey('spki', pubKey)
    .then((pubKeyAB) => {
        return BAtohex(bytesFromArray(new Uint8Array(pubKeyAB), 0, -1));
    });
}

/**
 * Returns a Promise which will resolve to the PEM string of the given CryptoKey
 * @param k - the CryptoKey to convert to PEM
 * @returns a Promise which will resolve to the PEM string of the given CryptoKey
 */

function subtleKeyToPEM(k) {
    const prefix = "-----BEGIN " + (k.type == "private" ? "PRIVATE KEY" : "PUBLIC KEY") + "-----\n";
    const suffix = "\n-----END " + (k.type == "private" ? "PRIVATE KEY" : "PUBLIC KEY") + "-----";

    return crypto.subtle.exportKey(k.type == "private" ? 'pkcs8' : 'spki', k)
    .then((pemStrAB) => {
        // convert the bytes from the ArrayBuffer into a single hex string
        return hextob64(BAtohex(bytesFromArray(new Uint8Array(pemStrAB), 0, -1)));
    }).then((pemStr) => {
        // add the prefix and suffix, and split the hex string into 64 character lines
        return prefix + pemStr.match(/.{1,64}/g).join('\n') + suffix;
    });
}

/**
 * Returns a Promise which resolves to the PEM string of a public key from either a
 * CryptoKey or a keypair previously generated by generateKeypair
 * 
 * @param kp - Either a CryptoKey public key or a keypair previously generated by generateKeypair
 * @returns a Promise which resolves to the PEM string
 */
function getPublicKeyPEM(kp) {
    let pubKey = (kp instanceof CryptoKey) ? kp : kp.publicKey;
    return subtleKeyToPEM(pubKey);
}

/**
 * Returns a Promise which resolves to the PEM string of a private key from either a
 * CryptoKey or a keypair previously generated by generateKeypair
 * 
 * @param kp - Either a CryptoKey private key or a keypair previously generated by generateKeypair
 * @returns a Promise which resolves to the PEM string
 */
function getPrivateKeyPEM(kp) {
    let privKey = (kp instanceof CryptoKey) ? kp : kp.privateKey;
    return subtleKeyToPEM(privKey);
}

/**
 * Given a particular algorithm ID and the private key hex bytes, return a Promise which resolves to
 * the private key as a CryptoKey
 * 
 * @param algId - The desired algId from the supported algorithms
 * @param hex - The hex string of the private key, as previous obtained from getPrivateKeyHex
 * @returns a Promise which resolves to the private key as a CryptoKey
 */
function getPrivateKeyFromHex(algId, hex) {
    return new Promise((resolve, reject) => {
        let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
        if (supportedAlgInfo) {
            crypto.subtle.importKey(
                "pkcs8", 
                new Uint8Array(b64toBA(hextob64(hex))),
                supportedAlgInfo.createParams,
                true,
                ["sign"]
            ).then(key => {
                resolve(key);
            }).catch((e) => {
                reject(e);
            });
        } else {
            reject(new Error("Unsupported algorithm: " + algId));
        }
    });
}

/**
 * Given a particular algorithm ID and the public key hex bytes, return a Promise which resolves to
 * the public key as a CryptoKey
 * 
 * @param algId - The desired algId from the supported algorithms
 * @param hex - The hex string of the public key, as previous obtained from getPublicKeyHex
 * @returns a Promise which resolves to the public key as a CryptoKey
 */

function getPublicKeyFromHex(algId, hex) {
    return new Promise((resolve, reject) => {
        let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
        if (supportedAlgInfo) {
            crypto.subtle.importKey(
                "spki", 
                new Uint8Array(b64toBA(hextob64(hex))),
                supportedAlgInfo.createParams,
                true,
                ["verify"]
            ).then(key => {
                resolve(key);
            }).catch((e) => {
                reject(e);
            });
        } else {
            reject(new Error("Unsupported algorithm: " + algId));
        }
    });
}

/**
 * Returns a Promise which resolves to the COSE public key from either a
 * CryptoKey public key or a keypair previously generated by generateKeypair
 * 
 * @param algId - The desired algId from the supported algorithms
 * @param kp - Either a CryptoKey public key or a keypair previously generated by generateKeypair
 * @returns a Promise which resolves to the COSE public key
 */
async function getPublicKeyCOSE(algId, kp) {
    return new Promise((resolve, reject) => {
        let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
        if (supportedAlgInfo) {
            return supportedAlgInfo.getPublicKeyCOSE(kp).then(coseKey => {
                resolve(coseKey);
            }).catch((e) => {
                reject(e);
            });
        } else {
            reject(new Error("Unsupported algorithm: " + algId));
        }
    });
}

/**
 * Returns a Promise which resolves to the CryptoKey public key from a coseKey if possible
 * 
 * @param coseKey - The coseKey from which to generate a public CryptoKey
 * @returns a Promise which resolves to the CryptoKey
 */
function getPublicKeyFromCOSE(coseKey) {
    return new Promise((resolve, reject) => {
        let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.coseKeyType == coseKey["1"] && alg.coseKeyAlg == coseKey["3"]);
        if (supportedAlgInfo) {
            supportedAlgInfo.getPublicKeyFromCOSE(coseKey)
            .then((publicKey) => {
                resolve(publicKey);
            }).catch((e) => {
                reject(e);
            });
        } else {
            reject(new Error("Unsupported key type and or algorithm in coseKey: " + JSON.stringify(coseKey)));
        }
    });
}

/**
 * Returns a Promise which resolves to the JWK public key from a coseKey if possible
 * 
 * @param coseKey - The coseKey from which to generate a JWK
 * @returns a Promise which resolves to the JWK
 */
function getJWKPublicKeyFromCOSE(coseKey) {
    return getPublicKeyFromCOSE(coseKey)
    .then((pk) => {
        return crypto.subtle.exportKey('jwk', pk);
    });
}

/**
 * Returns a Promise which resolves to the PEM public key from a coseKey if possible
 * 
 * @param coseKey - The coseKey from which to generate PEM
 * @returns a Promise which resolves to the PEM
 */
function getPEMPublicKeyFromCOSE(coseKey) {
    return getPublicKeyFromCOSE(coseKey)
    .then((pk) => {
        return subtleKeyToPEM(pk);
    });
}

/**
 * Returns a Promise which converts the bytes of an asn1-encoded X509 ceritificate or raw public key
 * into a CryptoKey public key
 * 
 * @param cert - The bytes of the asn1-encoded X509 certificate or raw public key
 * @param verificationAlgorithmId - The verification algorithm id of the public key
 * @returns a Promise which resolves to the CryptoKey public key
 */
function getPublicKeyFromCertBytes(cert, verificationAlgorithmId) {
    return new Promise((resolve, reject) => {
        if (cert != null && cert.length == 65 && cert[0] == 0x04) {
            // assume this is a raw public key EC
            crypto.subtle.importKey(
                "raw",
                new Uint8Array(cert).buffer,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ["verify"]
            ).then((pk) => {
                resolve(pk);
            }).catch((e) => {
                reject(e);
            });
        } else {
            // assume this is an X509 certificate - we need to extract the spki and import that
            let supportedSPKIAlgorithms = [
                // EC public key
                "1.2.840.10045.2.1",

                // RSA public key
                "1.2.840.113549.1.1.1"
            ];

            // this is really a sanity check for the types of subject public keys we support in a certificate
            let x509Cert = mycertutil.parseCertificate(cert);
            let spkiAlgorithm = x509Cert.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
            if (supportedSPKIAlgorithms.indexOf(spkiAlgorithm) < 0) {
                reject("Certificate subject public key algorithm " + spkiAlgorithm + " is not supported yet.");
            }

            let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === verificationAlgorithmId);
            if (supportedAlgInfo == null) {
                reject("Verification algorithm " + verificationAlgorithmId + " is not supported.");
            }

            crypto.subtle.importKey(
                'spki',
                new Uint8Array(x509Cert.tbsCertificate.subjectPublicKeyInfo.asn1.raw).buffer,
                supportedAlgInfo.createParams,
                true,
                ["verify"]
            ).then((pk) => {
                resolve(pk);
            }).catch((e) => {
                reject(e);
            });
        }
    });
}

/**
 * Encodes a number as an ASN.1 length and returns result as a hex string
 */
function asn1encodeLengthAsHex(len) {
    let result = null;
    if (len > 0 && len < 128) {
        result = len.toString(16);
    } else if (len > 0) {
        // long form encoding
        let lenHex = len.toString(16);
        // prefix with a zero if not an even number of hex chars
        if (lenHex.length%2 != 0) {
            lenHex = "0" + lenHex;
        }
        let numBytesForHexChars = lenHex.length / 2;
        result = (128+numBytesForHexChars).toString(16) + lenHex;

    }
    return result;
}

/**
 * Given an algorithm ID and the private key as a CryptoKey, return a Promise which resolves to 
 * the bytes of a signature over the data in a format suitable for WebAuthn signatures
 * 
 * @param algId - The desired signing algorithm ID
 * @param privateKey - The CryptoKey private key to sign with
 * @param data - The bytes of the data to sign
 * @returns - A Promise which resolves to the bytes of the signature as an array
 */
function signBytesWithPrivateKey(algId, privateKey, data) {
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);
    return crypto.subtle.sign(supportedAlgInfo.signParams, privateKey, new Uint8Array(data).buffer)
    .then((sigArrayBuffer) => {
        // ECDSA signatures need to be ASN.1 encoded per https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
        // inspiration from: https://stackoverflow.com/questions/39554165/ecdsa-signatures-between-node-js-and-webcrypto-appear-to-be-incompatible
        let result = null;
        if (algId === -7 || algId == -35 || algId == -36) {
            // Extract r and s and format in ASN1
            let signatureHex = BAtohex(bytesFromArray(new Uint8Array(sigArrayBuffer), 0, -1));
            let r = signatureHex.substring(0, signatureHex.length/2);
            let s = signatureHex.substring(signatureHex.length/2);
            let rPre = true;
            let sPre = true;

            // remove any zero-byte prefixes of r
            while(r.indexOf('00') === 0) {
                r = r.substring(2);
                rPre = false;
            }

            // pad r with leading zeros if necessary to make it unsigned
            if (rPre && parseInt(r.substring(0, 2), 16) > 127) {
                r = '00' + r;
            }

            // remove any zero-byte prefixes of s
            while(s.indexOf('00') === 0) {
                s = s.substring(2);
                sPre = false;
            }

            // pad s with leading zeros if necessary to make it unsigned
            if(sPre && parseInt(s.substring(0, 2), 16) > 127) {
                s = '00' + s;
            }

            // encode the two hex bytes of r and s in ASN1 format
            let payloadHex = '02' + asn1encodeLengthAsHex(r.length/2) + r + '02' + asn1encodeLengthAsHex(s.length/2) + s;
            // encode into a sequence
            let der = '30' + asn1encodeLengthAsHex(payloadHex.length/2) + payloadHex;

            // convert hex asn1 to base64url
            result = b64toBA(hextob64(der));
        } else {
            // for all other signature types, just supply raw signature output in base64url format
            result = bytesFromArray(new Uint8Array(sigArrayBuffer), 0, -1);
        }
        return result;
    });
}

/**
 * Given an algorithm ID and the private key as a CryptoKey, return a Promise which resolves to 
 * the bytes of a signature over the data in a format suitable for WebAuthn signatures
 * 
 * @param algId - The desired signature verification  algorithm ID
 * @param publicKey - The CryptoKey public key to verify with
 * @param sigBaseBytes - The bytes of the data to verify the signature over
 * @param sigBytes - The bytes of the signature to verify
 * @returns - A Promise which resolves to true if signature is valid, false otherwise
 */
async function validateSignature(algId, publicKey, sigBaseBytes, sigBytes) {
    let supportedAlgInfo = SUPPORTED_ALGS.find(alg => alg.algId === algId);

    let sigAB = null;

    if (algId === -7 || algId == -35 || algId == -36) {
        // reverse what we did in the signBytesWithPrivateKey function
        let xBytes = null;
        let yBytes = null;
        let sig = mycertutil.berToJavaScript(sigBytes);
        if (sig.cls == 0 && sig.tag == 16 && sig.structured) {
            let sigSeq = mycertutil.berListToJavaScript(sig.contents);
            if (sigSeq != null && sigSeq.length == 2) {
                let r = sigSeq[0];
                let s = sigSeq[1];
                if (r.cls == 0 && r.tag == 2 && !r.structured) {
                    xBytes = r.contents;
                    // strip any leading zero bytes
                    while (xBytes.length > 0 && xBytes[0] == 0x00) {
                        xBytes = xBytes.slice(1);
                    }
                } else {
                    console.log("Invalid r value in signature");
                }
                if (s.cls == 0 && s.tag == 2 && !s.structured) {
                    yBytes = s.contents;
                    // strip any leading zero bytes
                    while (yBytes.length > 0 && yBytes[0] == 0x00) {
                        yBytes = yBytes.slice(1);
                    }
                } else {
                    console.log("Invalid s value in signature");
                }
            } else {
                console.log("Invalid DER signature sequence");
            }

            if (xBytes != null && yBytes != null) {
                // join x and y into an array of bytes and set as ArrayBuffer
                sigAB = new Uint8Array(xBytes.concat(yBytes)).buffer;
            } else {
                console.log("Unable to determine signature components from DER signature");
            }
        } else {
            console.log("Invalid DER signature bytes");
        }
    } else {
        // for all other signature types, just use the bytes as is
        sigAB = new Uint8Array(sigBytes).buffer;
    }

    const sigBaseAB = new Uint8Array(sigBaseBytes).buffer;

    return crypto.subtle.verify(
        supportedAlgInfo.verifyParams,
        publicKey,
        sigAB,
        sigBaseAB
    );
}

/**
 * Utility function that returns a Promise to calculate the hex subject key identifier of a PEM certifcate
 * according to method 1 of https://tools.ietf.org/html/rfc5280#section-4.2.1.2
 * @param certBytes - The bytes of the asn1-encoded X509 certificate or raw public key
 * @returns {Promise<string>} - A Promise that resolves to the hex SKI
*/
function calculateSKI(certBytes) {
    let parsedCertificate = mycertutil.parseCertificate(certBytes);
    return crypto.subtle.digest(
        { name: 'SHA-1' },
        new Uint8Array(parsedCertificate.tbsCertificate.subjectPublicKeyInfo.bits.bytes)
    ).then(skiBytesAB => {
        return BAtohex(bytesFromArray(new Uint8Array(skiBytesAB), 0, -1));
    });
}

global.mykeyutil = {
    init: init,
    supportsPubKeyCredParam: supportsPubKeyCredParam,
    generateKeypair: generateKeypair,
    getPrivateKeyHex: getPrivateKeyHex,
    getPublicKeyHex: getPublicKeyHex,
    getPublicKeyPEM: getPublicKeyPEM,
    getPrivateKeyPEM: getPrivateKeyPEM,
    getPrivateKeyFromHex: getPrivateKeyFromHex,
    getPublicKeyFromHex: getPublicKeyFromHex,
    getPublicKeyCOSE: getPublicKeyCOSE,
    getPublicKeyFromCOSE: getPublicKeyFromCOSE,
    getJWKPublicKeyFromCOSE: getJWKPublicKeyFromCOSE,
    getPEMPublicKeyFromCOSE: getPEMPublicKeyFromCOSE,
    getPublicKeyFromCertBytes: getPublicKeyFromCertBytes,
    signBytesWithPrivateKey: signBytesWithPrivateKey,
    validateSignature: validateSignature,
    calculateSKI: calculateSKI
};

})(this);
