(function(global) {

	var GLOBALPOLICY = {
		/*
		 * Allowed attestation types
		 */
		allowedAttestationTypes: [ "Basic", "None", "AttCA", "Self" ],

		/*
		 * Supported attestation formats
		 */
		supportedAttestationFormats: [ "fido-u2f", "packed", "none", "tpm", "android-safetynet", "android-key", "apple" ],
		
		/*
		 * Supported packed attestation signature algorithms
		 */
		// -7 ECDSA256
		// -8 ALG_SIGN_ED25519_EDDSA_SHA256_RAW
		// -35 ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW
		// -36 ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW
		// -37 ALG_SIGN_RSASSA_PSS_SHA256_RAW
		// -38 ALG_SIGN_RSASSA_PSS_SHA384_RAW
		// -39 ALG_SIGN_RSASSA_PSS_SHA512_RAW
		// -257 ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW
		// -258 ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW
		// -259 ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW
		// -65535 ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW							
		supportedPackedAttestationAlgorithms: [ -7, -35, -37, -38, -39, -257, -258, -259, -65535 ],
		// I tried to do -36 however it seems KJUR does not support P521 for the Signature class
		// Same problem for -8
		// see: https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html#constructor
						
		/* Permitted age of android-safetynet attestations in milliseconds. Set to -1 to disable */
		androidSafetyNetMaxAttestationAgeMS: 60000
	}
			
	/**
	* debug loggining within these tools
	*/
	function debugLog(str) {
		console.log(str);
	}

	/**
	 * Compares two byte arrays, return true if they contain the same bytes
	 */
	function baEqual(ba1, ba2) {
		var result = false;
		if (Array.isArray(ba1) && Array.isArray(ba2)) {
			if (ba1.length == ba2.length) {
				var result = true;
				for (var i = 0; i < ba1.length && result; i++) {
					result = (ba1[i] == ba2[i]);
				}
			}
		}
		return result;
	}

	/**
	 * Utility function to check if all bytes in an array are zero
	 */
	function bytesZero(ba) {
		var result = false;
		if (Array.isArray(ba)) {
			result = true;
			for (var i = 0; i < ba.length && result; i++) {
				if (ba[i] != 0x00) {
					result = false;
				}
			}
		}
		return result;			
	}
	
	/**
	 * Extracts the bytes from an array beginning at index start, and continuing until 
	 * index end-1 or the end of the array is reached. Pass -1 for end if you want to 
	 * parse till the end of the array.
	 */
	function bytesFromArray(o, start, end) {
		// o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
		var len = o.length;
		if (len == null) {
			len = Object.keys(o).length;
		}
		
		var result = [];
		for (var i = start; (end == -1 || i < end) && (i < len); i++) {
			result.push(o[i]);
		}
		return result;
	}
	
	/**
	 * Convert a 4-byte array to a uint assuming big-endian encoding
	 * 
	 * @param buf
	 */
	function bytesToUInt32BE(buf) {
		var result = 0;
		if (buf != null && buf.length == 4) {
			result = ((buf[0] & 0xFF) << 24) | ((buf[1] & 0xFF) << 16) | ((buf[2] & 0xFF) << 8) | (buf[3] & 0xFF);
			return result;
		}
		return result;
	}
	
	/**
	 * Uses the ASN1 parser to look for a OID in a PEM x509 cert and return it's value as a hex string
	 */
	function findCertOIDValueHex(certPEM, oid) {
		var result = null;
		
		try {
			var x509Cert = new X509();
			x509Cert.readCertPEM(certPEM);
			var oidInfo = x509Cert.getExtInfo(oid);
			debugLog("The oidInfo is: " + JSON.stringify(oidInfo));
			if (oidInfo != null) {
				result = ASN1HEX.getV(pemtohex(certPEM), oidInfo.vidx);
			} else {
				debugLog("Did not find OID: " + oid + " in cert: " + certPEM);
			}
		} catch(e) {
			result = null;
			debugLog("Error parsing cert and looking for oid: " + oid);
			debugLog(e);
		}
		return result;
	}
	
	/**
	 * Returns the bytes of a sha1 message digest of either a string or byte array
	 * This is used when building the signature base string to verify
	 * registration data.
	 */
	function sha1(data) {
		var md = new KJUR.crypto.MessageDigest({
			alg : "sha1",
			prov : "cryptojs"
		});
		if (Array.isArray(data)) {
			md.updateHex(BAtohex(data));
		} else {
			md.updateString(data);
		}
		return b64toBA(hex2b64(md.digest()));
	}
	
	/**
	 * Returns the bytes of a sha256 message digest of either a string or byte array
	 * This is used when building the signature base string to verify
	 * registration data.
	 */
	function sha256(data) {
		var md = new KJUR.crypto.MessageDigest({
			alg : "sha256",
			prov : "cryptojs"
		});
		if (Array.isArray(data)) {
			md.updateHex(BAtohex(data));
		} else {
			md.updateString(data);
		}
		return b64toBA(hex2b64(md.digest()));
	}
	
	/**
	 * Returns the bytes of a sha384 message digest of either a string or byte array
	 * This is used when building the signature base string to verify
	 * registration data.
	 */
	function sha384(data) {
		var md = new KJUR.crypto.MessageDigest({
			alg : "sha384",
			prov : "cryptojs"
		});
		if (Array.isArray(data)) {
			md.updateHex(BAtohex(data));
		} else {
			md.updateString(data);
		}
		return b64toBA(hex2b64(md.digest()));
	}
	
	/**
	 * Returns the bytes of a sha512 message digest of either a string or byte array
	 * This is used when building the signature base string to verify
	 * registration data.
	 */
	function sha512(data) {
		var md = new KJUR.crypto.MessageDigest({
			alg : "sha512",
			prov : "cryptojs"
		});
		if (Array.isArray(data)) {
			md.updateHex(BAtohex(data));
		} else {
			md.updateString(data);
		}
		return b64toBA(hex2b64(md.digest()));
	}
	
	/**
	 * Converts the bytes of an asn1-encoded X509 ceritificate or raw public key
	 * into a PEM-encoded cert string
	 */
	function certToPEM(cert) {
		var keyType = "CERTIFICATE";
		asn1key = cert;
	
		if (cert != null && cert.length == 65 && cert[0] == 0x04) {
			// this is a raw public key - prefix with ASN1 metadata
			// SEQUENCE {
			// SEQUENCE {
			// OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
			// OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
			// }
			// BITSTRING <raw public key>
			// }
			// We just need to prefix it with constant 26 bytes of metadata
			asn1key = b64toBA(hextob64("3059301306072a8648ce3d020106082a8648ce3d030107034200"));
			Array.prototype.push.apply(asn1key, cert);
			keyType = "PUBLIC KEY";
		}
		var result = "-----BEGIN " + keyType + "-----\n";
		var b64cert = hextob64(BAtohex(asn1key));
		for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
			result += b64cert.slice(0, 64) + "\n";
		}
		if (b64cert.length > 0) {
			result += b64cert + "\n";
		}
		result += "-----END " + keyType + "-----\n";
		return result;
	}
	
	/**
	 * Performs signature validation as needed for FIDO registration and authenticate transactions.
	 * 
	 * @param sigBase -
	 *            signature base string bytes composed from the registration
	 *            response or sign response
	 * @param cert -
	 *            either an array of bytes of either the x509 attestation certificate 
	 *            from the registration data or the public key (for verifying sign responses),
	 *            OR the JSON object of the COSE encoded public key (used for FIDO2 
	 *            signature validation).
	 * @param sig -
	 *            bytes of the signature from the registration data or sign response
	 * @param alg -
	 *            The COSE algorithm identifier. Can be null in which case ECDSA will be assumed.
	 *            
	 * @returns true if the signature verified, false otherwise
	 */
	function verifyFIDOSignature(sigBase, cert, sig, alg) {
		var result = false;

		// default to ECDSA
		if (alg == null) {
			alg = -7;
		}

		var algMap = {
				"-7" : "SHA256withECDSA",
				"-35" : "SHA384withECDSA",
				"-36" : "SHA512withECDSA",
				"-37" : "SHA256withRSAandMGF1",
				"-38" : "SHA384withRSAandMGF1",
				"-39" : "SHA512withRSAandMGF1",
				"-257" : "SHA256withRSA",
				"-258" : "SHA384withRSA",
				"-259" : "SHA512withRSA",
				"-65535" : "SHA1withRSA"
			};

		var algStr = algMap['' + alg];
		if (algStr != null) {
			var verifier = new KJUR.crypto.Signature({
				"alg" : algStr
			});

			// find out what kind of public key validation material we have
			if (Array.isArray(cert)) {
				// x509 cert bytes, or EC public key bytes, as typically used by
				// FIDO-U2F
				verifier.init(certToPEM(cert));
			} else {
				// assume COSE key format
				verifier.init(coseKeyToPublicKey(cert));
			}

			verifier.updateHex(BAtohex(sigBase));
			// debugLog("BEFORE: " + result);
			result = verifier.verify(BAtohex(sig));
			// debugLog("AFTER: " + result);
		} else {
			debugLog("Unsupported algorithm in verifyFIDOSignature: " + alg);
		}

		if (!result) {
			// some extra debugging to try figure this out later
			debugLog("verifyFIDOSignature failed:  var sigBase="
					+ JSON.stringify(sigBase) + "; var cert="
					+ JSON.stringify(cert) + "; var sig=" + JSON.stringify(sig)
					+ "; var alg=" + alg + ";");
		}

		return result;
	}	

	/**
	* Build a human-readable string from the aaguid bytes
	*/
	function aaguidBytesToUUID(b) {
		var result = null;
		if (b != null && b.length == 16) {
			var s = BAtohex(b).toUpperCase();
			result = s.substring(0,8).concat("-",s.substring(8,12),"-",s.substring(12,16),"-",s.substring(16,20),"-",s.substring(20,s.length));
		}
		return result;
	}

	function coseKeyToECDSA256PublicKeyBytes(k) {
		var result = { "error": "unknown error", "keyBytes": null };
	
		if (k != null) {
			// see https://tools.ietf.org/html/rfc8152 for all these magic numbers
			var kty = k["1"];
			var alg = k["3"];
			var crv = k["-1"];
			
			// validate the key type is EC2
			if (kty == 2) {
				// validate the alg is ECDSA256
				if (alg == -7) {
					// validate the curve is P256
					if (crv == 1) {
						
						// obtain x and y coordinates for EC - these should each be 32 bytes long
						var xCoordinateBytes = bytesFromArray(k["-2"], 0, -1);
						var yCoordinateBytes = bytesFromArray(k["-3"], 0, -1);
						
						if (xCoordinateBytes.length == 32 && yCoordinateBytes.length == 32) {
							// seems ok build publicKey
							result["error"] = null;
							result["keyBytes"] = [ 0x04 ].concat(xCoordinateBytes, yCoordinateBytes);
						} else {
							result["error"] = "The size of the x or y co-ordinates is wrong";
						}
					} else {
						result["error"] = "The crv of the credential public key is invalid";
					}
				} else {
					result["error"] = "The alg of the credential public key is invalid";
				}
			} else {
				result["error"] = "The key type of the credential public key is invalid";
			}
		} else {
			result["error"] = "Credential public key is null";
		}
		
		return result;
	}
	
	function ECDSA256PublicKeyBytesToCoseKey(b) {
		var result = { "error": "unknown error", "coseKey": null };
		if (b != null && b.length == 65) {
			if (b[0] == 0x04) {
				var xCoordinateBytes = bytesFromArray(b, 1, 33);
				var yCoordinateBytes = bytesFromArray(b, 33, -1);
				
				// see https://tools.ietf.org/html/rfc8152 for all these magic numbers
				
				// set kty, alg and crv statically
				result["coseKey"] = { "1": 2, "3": -7, "-1": 1 };
				// now the bytes from the x and y co-ordinates
				result["coseKey"]["-2"] = new Uint8Array(xCoordinateBytes);
				result["coseKey"]["-3"] = new Uint8Array(yCoordinateBytes);
				result["error"] = null;			
			} else {
				result["error"] = "The provided elyptic curve public key bytes do not start with 0x04";
			}
		} else {
			result["error"] = "The provided elyptic curve public key bytes are of invalid length";
		}
		return result;
	}
	
	// see table 6.4 of https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
	function tpmECCCurvetoCoseCurve(tpmCurveID) {
		// default is no match
		var result = -1;
		if (tpmCurveID == 3) {
			result = 1;
		} else if (tpmCurveID == 4) {
			result = 2;
		} else if (tpmCurveID == 5) {
			result = 3;
		} else {
			// we don't support it
			result = -1;
		}
		return result;
	}

	function coseKeyToPublicKey(k) {
		var result = null;

		if (k != null) {
			// see https://tools.ietf.org/html/rfc8152
			// and https://www.iana.org/assignments/cose/cose.xhtml
			var kty = k["1"];
			var alg = k["3"];

			if (kty == 1) {
				// EdDSA key type
				validEDAlgs = [ -8 ];
				if (validEDAlgs.indexOf(alg) >= 0) {
					var crvMap = {
							"6" : "Ed25519",
							"7" : "Ed448"
						};
						var crv = crvMap['' + k["-1"]];
						if (crv != null) {
							debugLog("No support for EdDSA keys");
						} else {
							debugLog("Invalid crv: " + k["-1"] + " for ED key type");
						}

				} else {
					debugLog("Invalid alg: " + alg + " for ED key type");
				}
			} else if (kty == 2) {
				// EC key type
				validECAlgs = [ -7, -35, -36 ];

				if (validECAlgs.indexOf(alg) >= 0) {
					var crvMap = {
						"1" : "P-256",
						"2" : "P-384",
						"3" : "P-521" // this is not a typo. It is 521
					};
					var crv = crvMap['' + k["-1"]];
					if (crv != null) {
						// ECDSA
						var xCoordinate = bytesFromArray(k["-2"], 0, -1);
						var yCoordinate = bytesFromArray(k["-3"], 0, -1);

						if (xCoordinate != null && xCoordinate.length > 0
								&& yCoordinate != null && yCoordinate.length > 0) {
							result = KEYUTIL.getKey({
								"kty" : "EC",
								"crv" : crv,
								"x" : hextob64(BAtohex(xCoordinate)),
								"y" : hextob64(BAtohex(yCoordinate))
							});
						} else {
							debugLog("Invalid x or y co-ordinates for EC key type");
						}
					} else {
						debugLog("Invalid crv: " + k["-1"] + " for EC key type");
					}
				} else {
					debugLog("Invalid alg: " + alg + " for EC key type");
				}
			} else if (kty == 3) {
				// RSA key type
				validRSAAlgs = [ -37, -38, -39, -257, -258, -259, -65535 ];
				if (validRSAAlgs.indexOf(alg) >= 0) {
					var n = bytesFromArray(k["-1"], 0, -1);
					var e = bytesFromArray(k["-2"], 0, -1);
					if (n != null && n.length > 0 && e != null && e.length > 0) {
						result = KEYUTIL.getKey({
							"kty" : "RSA",
							"n" : hextob64(BAtohex(n)),
							"e" : hextob64(BAtohex(e))
						});
					} else {
						debugLog("Invalid n or e values for RSA key type");
					}
				} else {
					debugLog("Invalid alg: " + alg + " for RSA key type");
				}
			} else {
				debugLog("Unsupported key type: " + kty);
			}
		}
		return result;
	}

	function padToEvenNumberOfHexDigits(s) {
		let result = s;
		if (s.length%2 == 1) {
			result = '0'+s;
		}
		return result;
	}

	function publicKeyToCOSEKey(pk) {
		// should be one of RSAKey, KJUR.crypto.ECDSA as these are all we support
		let result = null;
		try {
			if (pk instanceof RSAKey) {
				result = {
					"1": 3,
					"3": -257,
					"-1": b64toBA(hextob64(padToEvenNumberOfHexDigits(pk.n.toString(16)))),
					"-2": b64toBA(hextob64(padToEvenNumberOfHexDigits(pk.e.toString(16))))
				};	
			} else if (pk instanceof KJUR.crypto.ECDSA) {
				// see table 5: https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
				const curveNameToAlgID = {
					"secp256r1": -7, 
					"secp384r1":  -35,
					"secp521r1": -36
				};
				let alg = (pk.curveName == null ? null : curveNameToAlgID[pk.curveName]);
				if (alg == null) {
					throw "Unrecognized ECDSA curve: " + pk.curveName;
				}


				// see Table 22: https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
				const curveNameToCurveKey = {
					"secp256r1": 1, 
					"secp384r1":  2,
					"secp521r1": 3
				};
				let keyID = curveNameToCurveKey[pk.curveName];
				if (keyID == null) {
					throw "Unrecognized ECDSA curve: " + pk.curveName;
				}

				// these keys come from Table 19: https://datatracker.ietf.org/doc/html/rfc8152#section-12.4.1
				result = {
					"1": 2,
					"3": alg,
					"-1": keyID,
					"-2": b64toBA(hextob64(pk.getPublicKeyXYHex().x)),
					"-3": b64toBA(hextob64(pk.getPublicKeyXYHex().y))
				};
			} else {
				throw "Unknown key type";
			}
		} catch(e) {
			console.log("Unsupported public key object: " + pk + " error: " + e);
		}

		return result;
	}


	function unpackAuthData(authDataBytes) {
		debugLog("unpackAuthData enter");
		var result = { 
			"status": false, 
			"rawBytes": null,
			"rpIdHashBytes": null, 
			"flags": 0, 
			"counter": 0, 
			"attestedCredData": null,
			"extensions": null
		};
		
		result["rawBytes"] = authDataBytes;
		
		if (authDataBytes != null && authDataBytes.length >= 37) {
			result["rpIdHashBytes"] = bytesFromArray(authDataBytes, 0, 32);
			result["flags"] = authDataBytes[32];
			result["counter"] = bytesToUInt32BE(bytesFromArray(authDataBytes, 33, 37));
					
			var nextByteIndex = 37;
			
			// check flags to see if there is attested cred data and/or extensions
			
			// bit 6 of flags - Indicates whether the authenticator added attested credential data.
			if (result["flags"] & 0x40) {
				result["attestedCredData"] = {};
				
				// are there enough bytes to read aaguid?
				if (authDataBytes.length >= (nextByteIndex + 16)) {
					result["attestedCredData"]["aaguid"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+16));
					nextByteIndex += 16;
					
					// are there enough bytes for credentialIdLength?
					if (authDataBytes.length >= (nextByteIndex + 2)) {
						var credentialIdLengthBytes = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+2));
						nextByteIndex += 2;
						var credentialIdLength = credentialIdLengthBytes[0] * 256 + credentialIdLengthBytes[1] 
						result["attestedCredData"]["credentialIdLength"] = credentialIdLength;
						
						// are there enough bytes for the credentialId?
						if (authDataBytes.length >= (nextByteIndex + credentialIdLength)) {
							result["attestedCredData"]["credentialId"] = bytesFromArray(authDataBytes, nextByteIndex, (nextByteIndex+credentialIdLength));
							nextByteIndex += credentialIdLength;
							
							var remainingBytes = bytesFromArray(authDataBytes, nextByteIndex, -1);
							//debugLog("remainingBytes: " + JSON.stringify(remainingBytes));
							
							//
							// try CBOR decoding the remaining bytes. 
							// NOTE: There could be both credentialPublicKey and extensions objects
							// so we use this special decodeVariable that Shane wrote to deal with
							// remaining bytes.
							//
							try {
								var decodeResult = CBOR.decodeVariable((new Uint8Array(remainingBytes)).buffer);
								result["attestedCredData"]["credentialPublicKey"] = decodeResult["decodedObj"];
								nextByteIndex += (decodeResult["offset"] == -1 ? remainingBytes.length : decodeResult["offset"]);
							} catch (e) {
								debugLog("Error CBOR decoding credentialPublicKey: " + e);
								nextByteIndex = -1; // to force error checking
							}
						} else {
							debugLog("unPackAuthData encountered authDataBytes not containing enough bytes for credentialId in attested credential data");
						}					
					} else {
						debugLog("unPackAuthData encountered authDataBytes not containing enough bytes for credentialIdLength in attested credential data");
					}				
				} else {
					debugLog("unPackAuthData encountered authDataBytes not containing enough bytes for aaguid in attested credential data");
				}
			}
			
			// bit 7 of flags - Indicates whether the authenticator has extensions.
			if (nextByteIndex > 0 && result["flags"] & 0x80) {
				try {
					result["extensions"] = CBOR.decode((new Uint8Array(bytesFromArray(authDataBytes, nextByteIndex, -1))).buffer);
					// must have worked
					nextByteIndex = authDataBytes.length;
				} catch (e) {
					debugLog("Error CBOR decoding extensions");
				}
			}
			
			// we should be done - make sure we processed all the bytes
			if (nextByteIndex == authDataBytes.length) {
				result["status"] = true;
			} else {
				debugLog("Remaining bytes in unPackAuthData. nextByteIndex: " + nextByteIndex + " authDataBytes.length: " + authDataBytes.length);
			}
		} else {
			debugLog("unPackAuthData encountered authDataBytes not at least 37 bytes long. Actual length: " + authDataBytes.length);
		}
	
		debugLog("unpackAuthData returning: " + JSON.stringify(result));
	
		return result;
	}
	
	/**
	 * Check that the fmt is one registered by IANA registry of WebAuthn-Registries
	 * 
	 * @param fmt
	 */
	function validateAttestationStatementFormat(fmt) {
		// based on policy (and capabilities)
		return (fmt != null && GLOBALPOLICY["supportedAttestationFormats"]
				.indexOf(fmt) >= 0);
	}
	
	function validateAttestationStatementNone(attestationObject, unpackedAuthData,
			clientDataHashBytes) {
		debugLog("validateAttestationStatementNone enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};
	
		if (unpackedAuthData["attestedCredData"] != null) {
			var attestedCredData = unpackedAuthData["attestedCredData"];
			var aaguid = attestedCredData["aaguid"];
			if (aaguid != null) {
				var credentialId = attestedCredData["credentialId"];
				if (credentialId != null) {
					var credentialPublicKey = attestedCredData["credentialPublicKey"];
					if (credentialPublicKey != null) {
						// if all checks ok, fill in result
						result["success"] = true;
						result["attestationType"] = "None";
						result["attestationTrustPath"] = [];
						result["aaguid"] = aaguid;
						result["credentialId"] = credentialId;
						result["credentialPublicKey"] = credentialPublicKey;
						result["format"] = attestationObject["fmt"];
						result["error"] = null;
					} else {
						result["error"] = "attested credential data does not contain credentialPublicKey";
					}
				} else {
					result["error"] = "attested credential data does not contain credentialId";
				}
			} else {
				result["error"] = "attested credential data does not contain aaguid";
			}
		} else {
			result["error"] = "authData does not contain attested credential data";
		}
	
		return result;
	}
	
	// s is a string similar to one of these:
	// "/C=SE/O=Yubico AB/OU=Authenticator Attestation/CN=Yubico U2F EE Serial 1955003842"
	// "/C=KR/ST=Seoul-Si/L=Gangnam-Gu/O=eWBM Co., Ltd./OU=Authenticator Attestation/CN=eWBM FIDO2 Certificate/E=info@e-wbm.com"
	function unpackSubjectDN(s) {
		var result = {};
		if (s != null) {
			var pieces = s.split('/');
			for (var i = 0; i < pieces.length; i++) {
				var nev = pieces[i].split(/=(.*)/);
				if (nev != null && nev.length == 3) {
					// ignore empty string at end of array
					// make sure we have consistent (upper case) keys
					result[nev[0].toUpperCase()] = nev[1];
				}
			} 
		}
		return result;
	}
	
	function verifyPackedAttestationCertificateRequirements(certBytes) {
		var result = true;
		debugLog("verifyPackedAttestationCertificateRequirements enter");
	
		// https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
		try {
			var x509Cert = new X509();
			x509Cert.readCertHex(BAtohex(certBytes));
			
			// SHANE
			debugLog("The attestation certificate is:");
			debugLog(certToPEM(certBytes));
	
			// check cert version
			result = (x509Cert.getVersion() == 3);
			if (!result) {
				debugLog("cert version was not 3: " + x509Cert.getVersion());
			}
	
			// check subject DN
			if (result) {
				var subjectString = x509Cert.getSubjectString();
				var subjectPieces = unpackSubjectDN(subjectString);
				if ("C" in subjectPieces && "O" in subjectPieces && "OU" in subjectPieces && "CN" in subjectPieces) {
					debugLog("Subject DN fields found. Country: " + subjectPieces["C"] + " Vendor: "
							+ subjectPieces["O"] + " OU: " + subjectPieces["OU"]
							+ " CN: " + subjectPieces["CN"]);
					
					// really should do further validation of "C" in particular

					// validate OU
					if (result) {
						if (subjectPieces["OU"] != "Authenticator Attestation") {
							debugLog("Attestation certificate subject DN is not the literal string: 'Authenticator Attestation'");
							result = false;
						}
					}
				} else {
					result = false;
				}
				
				if (!result) {
					debugLog("subject DN does not contain required fields: "
							+ subjectString);
				}
			}
	
			// check for aaguid in attestation cert
			if (result) {
				// how should I know this - let's just say "false" until told
				// otherwise. The eWMB attestation cert is such an example.
				var isAttestationRootCertUsedForMultipleModels = false;
	
				var oidInfo = x509Cert.getExtInfo("1.3.6.1.4.1.45724.1.1.4");
				if (oidInfo != null) {
					var aaguid = ASN1HEX.getV(BAtohex(certBytes), oidInfo.vidx);
					// 16 bytes is 32 hex chars
					if (aaguid != null && aaguid.length == 32) {
						if (!oidInfo.critical) {
							// ok so far
							result = true;
						} else {
							debugLog("oid marked critical");
							result = false;
						}
					} else {
						debugLog("aaguid invalid: " + aaguid);
						result = false;
					}
				} else {
					debugLog("oid extension not found - we won't mark this as fatal unless it's required");
					if (isAttestationRootCertUsedForMultipleModels) {
						debugLog("oid extension not found and apparently it was required");
						result = false;
					}
				}
				
				if (!result) {
					debugLog("certificate did not contain valid aaguid OID extenstion");
				}
			}
	
			// check basic constraints
			if (result) {
				var basicConstraints = x509Cert.getExtBasicConstraints();
				debugLog("*************  basicConstraints: " + basicConstraints);
				result = (basicConstraints == null || !(basicConstraints["cA"] == true));
	
				if (!result) {
					debugLog("CA flagged as true in BasicConstraints");
				}
			}
	
			// no further checks since AIA and CRL distribution point are optional
		} catch (e) {
			debugLog("verifyPackedAttestationCertificateRequirements error parsing x509 certificate: "
					+ e);
			result = false;
		}
	
		debugLog("verifyPackedAttestationCertificateRequirements returning: "
						+ result);
		return result;
	}
	
	function verifyTPMAttestationCertificateRequirements(certBytes) {
		var result = true;
		debugLog("verifyTPMAttestationCertificateRequirements enter");
	
		// https://www.w3.org/TR/webauthn/#tpm-cert-requirements
		try {
			var x509Cert = new X509();
			x509Cert.readCertHex(BAtohex(certBytes));
			
			// check cert version
			result = (x509Cert.getVersion() == 3);
			if (!result) {
				debugLog("cert version was not 3: " + x509Cert.getVersion());
			}
	
			// check subject is empty
			if (result) {
				debugLog("about to call getSubjectHex");
				var subjectHex = x509Cert.getSubjectHex();
				if (subjectHex == null || subjectHex != "3000") {
					result = false;
					debugLog("subject DN is not empty: " + subjectString);				
				}
			}
	
			// The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
			
			// TODO - finish this
		} catch (e) {
			debugLog("verifyTPMAttestationCertificateRequirements error parsing x509 certificate: "
					+ e);
			result = false;
		}
	
		debugLog("verifyTPMAttestationCertificateRequirements returning: "
						+ result);
		return result;
	}
	
	/*
	 * Given the bytes of an x509 attestation certificate, per step 2, sub-bullet 3
	 * of https://www.w3.org/TR/webauthn/#packed-attestation check if it contains an
	 * OID "1.3.6.1.4.1.45724.1.1.4" and if it does, that it matches the aaguid from
	 * the authentication data
	 */
	function packedAttestationOIDCheck(x5cBytes, unpackedAuthData) {
		var result = false;
		var oidValueHex = findCertOIDValueHex(certToPEM(x5cBytes),
				"1.3.6.1.4.1.45724.1.1.4");
		if (oidValueHex != null) {
			var aaguidHex = null;
			if (unpackedAuthData["attestedCredData"]["aaguid"] != null) {
				aaguidHex = BAtohex(unpackedAuthData["attestedCredData"]["aaguid"]);
			}
			debugLog("oidValueHex: " + oidValueHex + " aaguidHex: " + aaguidHex);
			result = (aaguidHex != null && aaguidHex == oidValueHex);
		} else {
			debugLog("Warning: Did not find OID 1.3.6.1.4.1.45724.1.1.4 in x5cBytes");
			// this is apparently ok since it only says to check against aaguid if
			// the oid exists
			result = true;
		}
		return result;
	}
	
	function tpmAttestationOIDCheck(x5cBytes, unpackedAuthData) {
		// this is actually the same as the packed attestation oid check
		return packedAttestationOIDCheck(x5cBytes, unpackedAuthData);
	}
	
	function validateAttestationStatementFIDOU2F(attestationObject,
			unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementFIDOU2F enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};
		// see https://www.w3.org/TR/webauthn/#fido-u2f-attestation
		var attStmt = attestationObject["attStmt"];
		if (attStmt != null) {

			// let's validate the attested credential data
			if (unpackedAuthData["attestedCredData"] != null) {
				var attestedCredData = unpackedAuthData["attestedCredData"];
				var aaguid = attestedCredData["aaguid"];
				if (aaguid != null) {
					if (bytesZero(aaguid)) {
						var credentialId = attestedCredData["credentialId"];
						if (credentialId != null) {
							var credentialPublicKey = attestedCredData["credentialPublicKey"];
							if (credentialPublicKey != null) {
								// unpack and validate the cose key
								// (https://tools.ietf.org/html/rfc8152)
								var coseKeyValidationResult = coseKeyToECDSA256PublicKeyBytes(credentialPublicKey);

								if (coseKeyValidationResult["keyBytes"] != null) {
									/* 
									 * obtain the signature bytes and x509 cert array from the attStmt
									 */
									var sig = attestationObject["attStmt"]["sig"];
									if (sig != null) {

										var attStmtSigBytes = bytesFromArray(sig, 0, -1);
										var x5c = attestationObject["attStmt"]["x5c"];
										if (x5c != null && x5c.length > 0) {
											var attStmtx5c = [];
											for (var i = 0; i < x5c.length; i++) {
												attStmtx5c.push(bytesFromArray(x5c[i], 0, -1));
											}

											// verification procedure
			
											/* 
											 * part 1 of verification procedure: is to extract 
											 * attStmt CBOR data - that was done before calling
											 * this method
											 */
			
											/*
											 * part 2 of verification procedure: verify that
											 * attCert public key is EC with P-256 curve
											 */
											var attCert = attStmtx5c[0];
											var pemAttCert = certToPEM(attCert);
											var x509AttCert = new X509();
											x509AttCert.readCertPEM(pemAttCert);
											var attCertPublicKey = x509AttCert
													.getPublicKey();
											if (attCertPublicKey.type == "EC"
													&& attCertPublicKey
															.getShortNISTPCurveName() == "P-256") {
			
												/*
												 * part 3 of verification procedure: extract
												 * rpIdHash, credentialId and credential
												 * public key
												 */
												var rpidhashBytes = bytesFromArray(
														attestationObject["authData"], 0,
														32);
												
												/*
												 * credentialId and credential public key
												 * have already been parsed above
												 */
			
												/* 
												 * part 4 of verification procedure: build publicKeyU2F
												 */
												publicKeyU2F = coseKeyValidationResult["keyBytes"];

												/*
												 * part 5 of verification procedure: build verificationData
												 */
												if (clientDataHashBytes != null && clientDataHashBytes.length > 0) {
													var verificationData = [ 0x00 ].concat(
															rpidhashBytes, clientDataHashBytes,
															credentialId, publicKeyU2F);
				
													// finally, let's verify the signature
													result.success = verifyFIDOSignature(
															verificationData, attCert,
															attStmtSigBytes, null);
				
													if (result.success) {
														result["attestationType"] = "Basic";
														result["attestationTrustPath"] = attStmtx5c;
														result["aaguid"] = aaguid;
														result["credentialId"] = credentialId;
														result["credentialPublicKey"] = credentialPublicKey;
														result["format"] = attestationObject["fmt"];
														result["error"] = null;
													} else {
														result["error"] = "Unable to validate fido-u2f signature";
													}
												} else {
													result["error"] = "Not enough information to perform fido-u2f signature validation";
												}
											} else {
												result["error"] = "Public key algorithm in attestation certificate is invalid";
											}
										} else {
											result["error"] = "attestation statement did not contain valid x5c";
										}
									} else {
										result["error"] = "attestation statement did not contain signature";	
									}
								} else {
									// error must be set
									result["error"] = coseKeyValidationResult["error"];
								}
							} else {
								result["error"] = "attested credential data does not contain credentialPublicKey";
							}
						} else {
							result["error"] = "attested credential data does not contain credentialId";
						}
					} else {
						result["error"] = "aaguid was not zeros";
					}
				} else {
					result["error"] = "attested credential data does not contain aaguid";
				}
			} else {
				result["error"] = "authData does not contain attested credential data";
			}
		} else {
			result["error"] = "attStmt missing from attestationObject";
		}
		debugLog("validateAttestationStatementFIDOU2F exit: " + JSON.stringify(result));
		return result;
	}
	
	function validateAttestationStatementPacked(attestationObject,
			unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementPacked enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};
	
		// see https://www.w3.org/TR/webauthn/#packed-attestation
		var attStmt = attestationObject["attStmt"];
		if (attStmt != null) {
			// get the alg from the packedStmtFormat - complete validation of alg
			// value happens later
			var alg = attStmt["alg"];
			if (alg != null) {
				// get the sig from the packedStmtFormat - complete validation of
				// sig value happens later
				var sig = (attStmt["sig"] != null ? bytesFromArray(attStmt["sig"],
						0, -1) : null);
				if (sig != null) {
					// see if there is x5c or ecdaaKeyId - these are optional in
					// packed attestation format
					var x5c = null;
					if (attStmt["x5c"] != null) {
						x5c = [];
						for (var i = 0; i < attStmt["x5c"].length; i++) {
							x5c.push(bytesFromArray(attStmt["x5c"][i], 0, -1));
						}
					}
	
					var ecdaaKeyId = null;
					if (attStmt["ecdaaKeyId"] != null) {
						ecdaaKeyId = bytesFromArray(attStmt["ecdaaKeyId"], 0, -1);
					}
	
					// verification procedure
	
					// part 1 of verification procedure: is to extract attStmt CBOR
					// data - that was done before calling this method
	
					// part 2 - is x5c present?
					if (x5c != null) {
						// attestation type is not ECDAA - validate sig according to
						// alg
						if (alg == "-7") {
							// ECDSA256 - we know how to deal with that
	
							// validate signature
							if (clientDataHashBytes != null && clientDataHashBytes.length > 0) {
								var verificationData = unpackedAuthData["rawBytes"]
										.concat(clientDataHashBytes);
								debugLog("about to perform ECDSA signature check");
								if (verifyFIDOSignature(verificationData, x5c[0], sig, alg)) {
									debugLog("ECDSA signature check OK!");
									// verify x5c requirements per
									// https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
									if (verifyPackedAttestationCertificateRequirements(x5c[0])) {
										// check cert for extension with OID
										// 1.3.6.1.4.1.45724.1.1.4
										if (packedAttestationOIDCheck(x5c[0],
												unpackedAuthData)) {
											//
											// not sure what to do with
											// credentialPublicKey since there I cannot
											// find any
											// validation rules as to what to do with
											// unpackedAuthData["attestedCredData"]["credentialPublicKey"]
											//
											var credentialPublicKey = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
											
											// done!
											result["success"] = true;
											result["attestationType"] = "Basic";
											result["attestationTrustPath"] = x5c;
											result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
											result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
											result["credentialPublicKey"] = credentialPublicKey;
											result["format"] = attestationObject["fmt"];
											result["error"] = null;
										} else {
											result["error"] = "packed attestation certificate did not oid check";
										}
									} else {
										result["error"] = "packed attestation certificate did not satisfy requirements";
									}
								} else {
									result["error"] = "packed attestation signature validation failed";
								}
							} else {
								result["error"] = "packed attestation not enough information to perform signature validation";
							}
						} else {
							// signature algorithm not supported by this implementation
							result["error"] = "packed attestation signature type: "
									+ alg + " not yet supported";
						}
					} else {
						if (ecdaaKeyId != null) {
							result["error"] = "packed attestation format using ecdaa not yet supported";	
						} else {
							// self attestation
							
							// Perform the verification steps in step 4 of https://www.w3.org/TR/webauthn/#packed-attestation
							
							// Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData
							var credentialPublicKey = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
							if (alg != null && credentialPublicKey["3"] != null && alg == credentialPublicKey["3"]) {
								
								// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
								if (GLOBALPOLICY.supportedPackedAttestationAlgorithms.indexOf(alg) >= 0) {
									// validate signature
									if (clientDataHashBytes != null && clientDataHashBytes.length > 0) {
										var verificationData = unpackedAuthData["rawBytes"]
												.concat(clientDataHashBytes);
										if (verifyFIDOSignature(verificationData, credentialPublicKey, sig, alg)) {

											// all ok
											result["success"] = true;
											result["attestationType"] = "Self";
											result["attestationTrustPath"] = [];
											result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
											result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
											result["credentialPublicKey"] = credentialPublicKey;
											result["format"] = attestationObject["fmt"];
											result["error"] = null;
										} else {
											result["error"] = "packed self attestation signature validation failed";
										}
									} else {
										result["error"] = "packed self attestation not enough information to perform signature validation";
									}
								} else {
									// signature algorithm not supported by this implementation
									result["error"] = "packed self attestation signature type: " + alg + " not yet supported";
								}
							} else {
								result["error"] = "packed self attestation alg: " + alg + " did not match credentialPublicKey algorithm: " + credentialPublicKey["3"];
							}
						}
					}
				} else {
					result["error"] = "packed attestation statment does not contain sig";
				}
			} else {
				result["error"] = "packed attestation statment does not contain alg";
			}
		} else {
			result["error"] = "attStmt missing from attestationObject";
		}
	
		debugLog("validateAttestationStatementPacked exit: " + JSON.stringify(result));
		return result;
	}
	
	/*
	 * Unpack the public area bytes from a TPM attestation. Most of the information required
	 * to do this was found here, which is a little sad because the TPM spec is undecipherable:
	 * https://github.com/w3c/webauthn/issues/984
	 * https://medium.com/webauthnworks/verifying-fido-tpm2-0-attestation-fc7243847498
	 */
	function unpackPublicArea(pubAreaBytes) {
		var result = { "valid": true, "error": null };
		
		// use data view to walk over the bytes
		var pubAreaBA = bytesFromArray(pubAreaBytes, 0,-1);
		result["rawBytes"] = pubAreaBA;

		var pubAreaArrayBuffer = (new Uint8Array(pubAreaBA)).buffer;
		
	    var dataview = new DataView(pubAreaArrayBuffer);
	    var index = 0;
	
	    // TPMI_ALG_PUBLIC type (2 bytes)
	    result["type"] = dataview.getUint16(index);
	    index += 2;
	    // presently we only support TPM_ALG_RSA and TPM_ALG_ECC
	    if (result["type"] != 0x0001 /* TPM_ALG_RSA */ && result["type"] != 0x0023) {
	    	result.valid = false;
	    	result.error = "TPM attestation only supports TPM_ALG_RSA and TPM_ALG_ECC, not: " + result["type"]; 
	    }
	
	    // TPMI_ALG_HASH nameAlg (2 bytes)
	    if (result.valid) {
		    result["nameAlg"] = dataview.getUint16(index);
		    index += 2;
	    }
	
	    // TPMA_OBJECT objectAttributes (4 bytes)
	    if (result.valid) {
		    result["objectAttributes"] = dataview.getUint32(index);
		    index += 4;
	    }
	
	    // TPM2B_DIGEST authPolicy
	    if (result.valid) {
		    var szBytes = getSizedBytes(dataview, index);
		    result["authPolicy"] = szBytes["bytes"];
		    index = szBytes["nextIndex"];
	    }
	
	    // TPMU_PUBLIC_PARMS parameters 
	    if (result.valid) {
	    	var parameters = {};
	    	if (result["type"] == 0x0001 /* TPM_ALG_RSA */ ) {
				// (at this point assumes TPMS_RSA_PARMS because type has been validated to TPM_ALG_RSA)
				// see table 12.2.3.5 of https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
	    		// read symmetric, scheme, keyBits and exponent
	    		parameters["symmetric"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["scheme"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["keyBits"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["exponent"] = dataview.getUint32(index);
	    		index += 4;
	    		if (parameters["exponent"] == 0) {
	    			parameters["exponent"] = 65537;
	    		}
			} else if (result["type"] == 0x0023 /* TPM_ALG_ECC */ ) {
				// (at this point assumes TPMS_ECC_PARMS because type has been validated to TPM_ALG_ECC)
				// see table 12.2.3.6 of https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
	    		// read symmetric, scheme, curveID and kdf
	    		parameters["symmetric"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["scheme"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["curveID"] = dataview.getUint16(index);
	    		index += 2;
	    		parameters["kdf"] = dataview.getUint16(index);
	    		index += 2;
	    	} else {
	    		// shouldn't get here
	    		result.valid = false;
	    		result.error = "Unsupported TPM algorithm type: " + result["type"];
	    	}
	    	result["parameters"] = parameters;
	    }
	    
	    // TPMU_PUBLIC_ID unique
		// see table 12.2.3.2 of https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
	    if (result.valid) {
			if (result["type"] == 0x0001 /* TPM_ALG_RSA */ ) {
				// TPM2B_PUBLIC_KEY_RSA
				var szBytes = getSizedBytes(dataview, index);
				debugLog("szBytes after reading TPMU_PUBLIC_ID: " + JSON.stringify(szBytes));
				result["unique"] = szBytes["bytes"];
				index = szBytes["nextIndex"];
			} else if (result["type"] == 0x0023 /* TPM_ALG_ECC */) {
				// TPMS_ECC_POINT (x and y coordinates)
				result["unique"] = {};
				var szBytes = getSizedBytes(dataview, index);
				result["unique"]["x"] = szBytes["bytes"];
				index = szBytes["nextIndex"];
				szBytes = getSizedBytes(dataview, index);
				result["unique"]["y"] = szBytes["bytes"];
				index = szBytes["nextIndex"];
			} else {
	    		// shouldn't get here
	    		result.valid = false;
	    		result.error = "Unsupported TPM algorithm type: " + result["type"];
			}
	    }
	    
	    if (result.valid) {
	    	// check we got all the bytes
		    if (index != pubAreaBA.length) {
		    	result.valid = false;
		    	result.error = "Unexpected leftover bytes in public area";
		    }
	    }
	
	    return result;
	}
	
	/*
	 * Unpack the certInfo bytes from a TPM attestation. Most of the information required
	 * to do this was found here, which is a little sad because the TPM spec is undecipherable:
	 * https://github.com/w3c/webauthn/issues/984
	 * https://medium.com/webauthnworks/verifying-fido-tpm2-0-attestation-fc7243847498
	 */
	function unpackCertInfo(certInfoBytes) {
		var result = { "valid": true, "error": null };
		
		// use data view to walk over the bytes
		var certInfoBA = bytesFromArray(certInfoBytes, 0,-1);
		result["rawBytes"] = certInfoBA;
		
		var certInfoArrayBuffer = (new Uint8Array(certInfoBA)).buffer;
		
	    var dataview = new DataView(certInfoArrayBuffer);
	    var index = 0;
	    
	    // TPM_GENERATED magic
	    result["magic"] = dataview.getUint32(index);
	    index += 4;
	    
	    // rest of parsing depends on this magic number being a specific magic number
	    if (result["magic"] != 0xff544347) {
	    	result.valid = false;
	    	result.error = "certInfo contains invalid TPM_GENERATED magic number: " + result["magic"];
	    }
	    
	    // TPMI_ST_ATTEST type
	    if (result.valid) {
	    	result["type"] = dataview.getUint16(index);
	    	index += 2;
	    	
	    	// we only support TPM_ST_ATTEST_CERTIFY
	    	if (result["type"] != 0x8017) {
	        	result.valid = false;
	        	result.error = "certInfo contains invalid TPMI_ST_ATTEST type: " + result["type"];
	    	}    	
	    }
	    
	    // TPM2B_NAME qualifiedSigner
	    if (result.valid) {
	    	var qualifiedSignerResult = parseTPM2BName(dataview, index);
	    	index = qualifiedSignerResult.nextIndex;
	    	result["qualifiedSigner"]  = {
	    		"digest": qualifiedSignerResult.digest,
	    		"handle": qualifiedSignerResult.handle
	    	};
	    }
	    
	    // TPM2B_DATA extraData
	    if (result.valid) {
		    var szBytes = getSizedBytes(dataview, index);
		    result["extraData"] = szBytes["bytes"];
		    index = szBytes["nextIndex"];
	    }
	    
	    // TPMS_CLOCK_INFO clockInfo
	    if (result.valid) {
	    	var clockInfo = {};
	    	// clock UINT64
	    	clockInfo["clock"] = bytesFromArray(new Uint8Array(dataview.buffer.slice(index, index+8)), 0, -1);
	    	index += 8;
	    	
	    	// resetCount UINT32
	    	clockInfo["resetCount"] = dataview.getUint32(index);
	    	index += 4;
	    	
	    	// restartCount UINT32
	    	clockInfo["restartCount"] = dataview.getUint32(index);
	    	index += 4;
	    	
	    	// safe TPMI_YES_NO (boolean)
	    	clockInfo["safe"] = (dataview.getUint8(index) != 0);
	    	index += 1;
	    	
	    	result["clockInfo"] = clockInfo;
	    }
	    
	    // UINT64 firmwareVersion
	    if (result.valid) {
	    	result["firmwareVersion"] = bytesFromArray(new Uint8Array(dataview.buffer.slice(index, index+8)), 0, -1);
	    	index += 8;
	    }
	    
	    // TPMU_ATTEST attested (depends on type)
	    if (result.valid) {
	    	var attested = {};
		    if (result["type"] == 0x8017) {
		    	// TPMS_CERTIFY_INFO
		    	var certify = {};
		    	// should have name and qualifiedName, both of type TPM2B_NAME
		    	var nameResult = parseTPM2BName(dataview, index);
		    	index = nameResult.nextIndex;
		    	certify["name"]  = {
		    		"digest": nameResult.digest,
		    		"handle": nameResult.handle
		    	};
		    	
		    	var qualifiedNameResult = parseTPM2BName(dataview, index);
		    	index = qualifiedNameResult.nextIndex;
		    	certify["qualifiedName"]  = {
		    		"digest": qualifiedNameResult.digest,
		    		"handle": qualifiedNameResult.handle
		    	};
		    	
		    	attested["certify"] = certify;
		    } else {
				// shouldn't get here
				result.valid = false;
				result.error = "Unsupported TPMI_ST_ATTEST type: " + result["type"];
		    }
		    result["attested"] = attested;
	    }
	    
	    if (result.valid) {
	    	// check we got all the bytes
		    if (index != certInfoBA.length) {
		    	result.valid = false;
		    	result.error = "Unexpected leftover bytes in certInfo";
		    }
	    }
	
		return result;
	}
	
	function getSizedBytes(dataview, index) {
		// first two bytes are the size
	    var sz = dataview.getUint16(index);
	    index += 2;
	    
	    // now get that many bytes from the dataview, if any
	    var bytes = null;
		if (sz > 0) {
			bytes = bytesFromArray(new Uint8Array(dataview.buffer.slice(index, index + sz)), 0, -1);
		}
	    index += sz; // not really needed becase we're done parsing
	    
	    var result = {
	    	"nextIndex": index,
	    	"bytes": bytes
	    };
	    
	    return result;
	}
	
	function parseTPM2BName(dataview,index) {

		var result = {
			"nextIndex": 0,
			"digest": null,
			"handle": null
		};

		var szBytes = getSizedBytes(dataview,index);
		// this gets updated regardless of whether the name is empty
		result.nextIndex = szBytes.nextIndex;

		if (szBytes.bytes != null && szBytes.bytes.length > 0) {
			// now parse those bytes to find the digest and handle
			var nameArrayBuffer = (new Uint8Array(szBytes.bytes)).buffer;
			
			var dataview2 = new DataView(nameArrayBuffer);
			var index2 = 0;
			var digest = dataview2.getUint16(index2);
			index2 += 2;
			var handle = bytesFromArray(new Uint8Array(dataview2.buffer.slice(index2)), 0, -1);
			
			
			result.digest = digest;
			result.handle = handle;
		}
		
		return result;
	}
	
	function validateAttestationStatementTPM(attestationObject, unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementTPM enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};

		// see https://www.w3.org/TR/webauthn/#tpm-attestation
		var valid = true;
		
		// check attestation statement is present
		var attStmt = attestationObject["attStmt"];
		if (attStmt == null) {
			valid = false;
			result["error"] = "attStmt missing from attestationObject";
		}
		
		// check the version is 2.0
		var attStmtVersion = null;
		if (valid) {
			attStmtVersion = attStmt["ver"];
			if (attStmtVersion != "2.0") {
				valid = false;
				result["error"] = "Unrecognized TPM attestation statement version: " + attStmtVersion;	
			}	
		}
		
		// verify there is an alg in attStmt
		var alg = null;
		if (valid) {
			alg = attStmt["alg"];
			debugLog("The TPM attestation statement algorithm is: " + alg);
			if (alg == null) {
				valid = false;
				result["error"] = "Missing alg in attestation statement";	
			}
		}
		
		// verify there is a sig in attStmt
		
		var sig = (attStmt["sig"] != null ? bytesFromArray(attStmt["sig"],
				0, -1) : null);
		if (valid) {
			if (sig == null) {
				valid = false;
				result["error"] = "Missing sig in attestation statement";	
			}
		}
		
		// verify there is certInfo in attStmt
		var certInfo = null;
		if (valid) {
			certInfo = attStmt["certInfo"];
			if (certInfo == null) {
				valid = false;
				result["error"] = "Missing certInfo in attestation statement";	
			}
		}
		
		// verify there is pubArea in attStmt
		var pubArea = null;
		if (valid) {
			pubArea = attStmt["pubArea"];
			if (pubArea == null) {
				valid = false;
				result["error"] = "Missing pubArea in attestation statement";	
			}
		}
		
		// if there is an x5c array, get it
		var x5c = null;
		if (valid) {
			if (attStmt["x5c"] != null) {
				x5c = [];
				for (var i = 0; i < attStmt["x5c"].length; i++) {
					x5c.push(bytesFromArray(attStmt["x5c"][i], 0, -1));
				}
			}
		}
		
		// if there is ecdaaKeyId, get it
		var ecdaaKeyId = null;
		if (valid) {
			ecdaaKeyId = attStmt["ecdaaKeyId"];
		}
		
		// depending on the alg, check for ecdaaKeyId or x5c
		// magic numbers found at: https://www.iana.org/assignments/cose/cose.xhtml
		var validTPMECDAAAlgs = [-260, -261];
		var validTPMRSAAlgs = [ -257, -258, -259, -65535 ];		
		
		if (valid) {
			// if ED256 or ED512, require ecdaaKeyId
			if (validTPMECDAAAlgs.indexOf(alg) >= 0) {
				if (ecdaaKeyId == null) {
					valid = false;
					result["error"] = "Missing ecdaaKeyId in attestation statement for given alg: " + alg;				
				} else {
					// TODO change this when we figure out how to support ED signature validation
					valid = false;
					result["error"] = "No implementation yet to support TPM with given alg: " + alg;				
				}
			} else if (validTPMRSAAlgs.indexOf(alg) >= 0) {
				if (x5c == null || !Array.isArray(x5c) || !(x5c.length > 0)) {
					valid = false;
					result["error"] = "Missing or bad x5c in attestation statement for given alg: " + alg;				
				}
			} else {
				// not sure what to do with this alg
				valid = false;
				result["error"] = "No implementation to support TPM with given alg: " + alg;				
			}
		}
		
		// verify the public key in pubArea is same as credentialPublicKey in the authData
		var unpackedPublicArea = null;
		if (valid) {
			unpackedPublicArea = unpackPublicArea(pubArea);
			debugLog("unpackedPublicArea: " + JSON.stringify(unpackedPublicArea));

			if (unpackedPublicArea.valid) {
				var credentialPublicKey = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
				var credentialPublicKeyObject = coseKeyToPublicKey(credentialPublicKey);
				
				// RSA and ECC are supported
				if (credentialPublicKeyObject.type == "RSA") {
					// check that both key types are RSA and the algorithms are the same
					if (valid) {
						if (!(unpackedPublicArea["type"] == 0x01 /* TPM_ALG_RSA */)) {
							valid = false;
							result["error"] = "pubArea key type is not TPM_ALG_RSA";
						}
					}
									
					// check that the exponents match
					if (valid) {
						if (credentialPublicKeyObject.e != unpackedPublicArea["parameters"]["exponent"]) {
							valid = false;
							result["error"] = "exponent mismatch between pubArea and credentialPublicKey";
						}
					}
					
					// check that 'n' matches. For some reason credentialPublicKeyObject.n doesn't match??
					// instead we compare the byte arrays, and that works
					if (valid) {
						debugLog("About to compare 'n'");
						var cpkNBytes = bytesFromArray(credentialPublicKey["-1"],0,-1);
						var pubAreaNBytes = bytesFromArray(unpackedPublicArea["unique"],0,-1);
						if (!baEqual(cpkNBytes, pubAreaNBytes)) {
							valid = false;
							result["error"] = "RSA 'n' mismatch between pubArea and credentialPublicKey";
						}
					}

				} else if (credentialPublicKeyObject.type == "EC") {
					// check that both key types are ECC and the parameters are the same
					if (valid) {
						if (!(unpackedPublicArea["type"] == 0x23 /* TPM_ALG_ECC */)) {
							valid = false;
							result["error"] = "pubArea key type is not TPM_ALG_ECC";
						}
					}

					if (valid) {
						// check curveID
						var coseCurveID = credentialPublicKey["-1"];
						var pubAreaCurveID = unpackedPublicArea["parameters"]["curveID"];
						if (!(coseCurveID == tpmECCCurvetoCoseCurve(pubAreaCurveID))) {
							valid = false;
							result["error"] = "pubArea curveID does not match attested credential curveID";
						}
					}

					if (valid) {
						// check x and y co-ordinates match
						var cpkxBytes = bytesFromArray(credentialPublicKey["-2"],0,-1);
						var cpkyBytes = bytesFromArray(credentialPublicKey["-3"],0,-1);
						var pubAreaxBytes = unpackedPublicArea["unique"]["x"];
						var pubAreayBytes = unpackedPublicArea["unique"]["y"];
						if (!baEqual(cpkxBytes, pubAreaxBytes)) {
							valid = false;
							result["error"] = "EC 'x' coordinate mismatch between pubArea and credentialPublicKey";
						}
						if (valid) {
							if (!baEqual(cpkyBytes, pubAreayBytes)) {
								valid = false;
								result["error"] = "EC 'y' coordinate mismatch between pubArea and credentialPublicKey";
							}
						}
					}
				} else {
					valid = false;
					result["error"] = "credentialPublicKey in attestedCredData is not an RSA or EC key";
				}
			} else {
				valid = false;
				result["error"] = "Error unpacking pubArea: " + unpackedPublicArea["error"];
			}
		}
		
		// concatenate authenticatorData and clientDataHash to form attToBeSigned
		var attToBeSigned = null;
		if (valid) {
			var attToBeSigned = unpackedAuthData["rawBytes"].concat(clientDataHashBytes);
		}
		
		// validate that certInfo is valid
		if (valid) {
			var unpackedCertInfo = unpackCertInfo(certInfo);
			debugLog("unpackedCertInfo: " + JSON.stringify(unpackedCertInfo));
			if (unpackedCertInfo.valid) {
				// we have already checked during the unpack that:
				// magic is set to TPM_GENERATED_VALUE and
				// type is set to TPM_ST_ATTEST_CERTIFY
				
				// now verify extraData is set to the hash of attToBeSigned using alg
				
				// default to this, but override to sha1 for the old Microsoft alg
				// we can/should add other checks on the hash algorithm too
				var hashFunc = sha256; 
				if (alg == -65535) {
					debugLog("WARNING: using sha1 hash function verifying extraData");
					hashFunc = sha1;
				}
				var computedHash = hashFunc(attToBeSigned); 
				if (!baEqual(computedHash, unpackedCertInfo["extraData"])) {
					valid = false;
					result["error"] = "certInfo extraData hash value invalid";
				}
				
				// Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in 
				// [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, 
				// as computed using the algorithm in the nameAlg field of pubArea using the procedure 
				// specified in [TPMv2-Part1] section 16
				
				var certInfoAttestedNameHandle = unpackedCertInfo["attested"]["certify"]["name"]["handle"];
				var certInfoAttestedNameDigest = unpackedCertInfo["attested"]["certify"]["name"]["digest"];
				
				// figure out what hash to use
				hashFunc = null;
				if (certInfoAttestedNameDigest == 0x04 /* sha1 */) {
					hashFunc = sha1;
				} else if (certInfoAttestedNameDigest == 0x0B /* sha256 */ ) {
					hashFunc = sha256;
				} else if (certInfoAttestedNameDigest == 0x0C /* sha384 */ ) {
					hashFunc = sha384;
				} else if (certInfoAttestedNameDigest == 0x0D /* sha512 */ ) {
					hashFunc = sha512;
				} else {
					valid = false;
					result["error"] = "Unsupported digest algorithm for certInfo attested name: " + certInfoAttestedNameDigest;
				}
				
				if (valid) {
					// hash the raw pubArea bytes with this algorithm
					var pubAreaHashBytes = hashFunc(unpackedPublicArea["rawBytes"]);
					
					// check that the certInfo name handle matches this hash
					if (!baEqual(pubAreaHashBytes, certInfoAttestedNameHandle)) {
						valid = false;
						result["error"] = "certInfo certified name handle did not match hash of public area bytes";
					}
				}
				
				// Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] 
				// section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These 
				// fields MAY be used as an input to risk engines.			
			} else {
				valid = false;
				result["error"] = "Error unpacking certInfo: " + unpackedCertInfo["error"];
			}
			
			// what happens next depends on x5c, and ecdaaKeyId
			if (x5c != null) {
				// If x5c is present, this indicates that the attestation type is not ECDAA. In this case:
				
				// Verify the sig is a valid signature over certInfo using the attestation public key 
				// in x5c with the algorithm specified in alg
				var attStmtSigBytes = bytesFromArray(sig, 0, -1);
				
				if (!verifyFIDOSignature(unpackedCertInfo["rawBytes"], x5c[0], attStmtSigBytes, alg)) {
					valid = false;
					result["error"] = "Signature validation of certInfo bytes failed";
				}
				
				if (valid) {
					if (!verifyTPMAttestationCertificateRequirements(x5c[0])) {
						valid = false;
						result["error"] = "TPM attestation certificate did not satisfy requirements";
					}
				}
				
				if (valid) {
					if (!tpmAttestationOIDCheck(x5c[0], unpackedAuthData)) {
						valid = false;
						result["error"] = "TPM attestation certificate OID check failed";
					}
				}
				
				if (valid) {
					// done!
					result["success"] = true;
					result["attestationType"] = "AttCA";
					result["attestationTrustPath"] = x5c;
					result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
					result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
					result["credentialPublicKey"] = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
					result["format"] = attestationObject["fmt"];
					result["error"] = null;
				}
			} else if (ecdaaKeyId != null) {
				// not yet supported
				valid = false;
				result["error"] = "Validation of TPM attestation with ecdaaKeyId not yet supported";
			} else {
				// shouldn't get here
				valid = false;
				result["error"] = "Neither x5c or exdaaKeyId was present";
			}
			
		}
		
		debugLog("validateAttestationStatementTPM exit: " + JSON.stringify(result));
		return result;
	}

	function validateAttestationStatementAndroidSafetyNet(attestationObject, unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementAndroidSafetyNet enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};

		// see https://www.w3.org/TR/webauthn/#android-safetynet-attestation
		var valid = true;
		
		// check attestation statement is present
		var attStmt = attestationObject["attStmt"];
		if (attStmt == null) {
			valid = false;
			result["error"] = "attStmt missing from attestationObject";
		}
		
		// get the version
		// The version number of Google Play Services responsible for providing the SafetyNet API.
		var attStmtVersion = null;
		if (valid) {
			attStmtVersion = attStmt["ver"];
			if (attStmtVersion == null || attStmtVersion.length <= 0) {
				valid = false;
				result["error"] = "Missing version in attestation statement";	
			}
			debugLog("Android SafetyNet attestation statement version: " + attStmtVersion);
		}
		
		// get the response in attStmt
		var attStmtResponseBytes = null;
		if (valid) {
			attStmtResponseBytes = bytesFromArray(attStmt["response"], 0, -1);
			if (attStmtResponseBytes == null || attStmtResponseBytes.length <= 0) {
				valid = false;
				result["error"] = "Missing response in attestation statement";	
			}
		}
		
		// verification steps
		
		// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
		// This is done by way of decoding and checking for non-null values above. Now we just decode the response bytes to a JWS.
		var jws = null;
		try {
			var sJWS = hextoutf8(BAtohex(attStmtResponseBytes));
			jws = KJUR.jws.JWS.parse(sJWS);
		} catch (e) {
			valid = false;
			result["error"] = "Error parsing response to JWS";
		}
		
		var alg = null;
		var x5c = null;
		if (valid) {
			// check signature of JWS - should be RS256 and first cert in x5c of header should be the signer
			alg = jws.headerObj["alg"];
			if (alg != null && alg == "RS256") {
				
				// make x5c an array of the bytes of the trust chain, like all the other attestation types
				x5c = [];
				if (jws.headerObj["x5c"] != null && Array.isArray(jws.headerObj["x5c"])) {
					for (var i = 0; i < jws.headerObj["x5c"].length; i++) {
						x5c.push(b64toBA(jws.headerObj["x5c"][i]));
					}
				}

				if (x5c != null && x5c.length > 0) {
					var isValid = KJUR.jws.JWS.verify(sJWS, certToPEM(x5c[0]), [alg]);
					
					if (!isValid) {
						valid = false;
						result["error"] = "JWS signature failed to validate";
					}										
				} else {
					valid = false;
					result["error"] = "Missing x5c in JWS header";
				}
			} else {
				valid = false;
				result["error"] = "Unexpected alg in JWS header";				
			}
		}
		
		
		// Verify that response is a valid SafetyNet response of version ver.
		
		if (valid) {
			// See https://developer.android.com/training/safetynet/attestation		
			// an example from early testing: {"nonce":"hbAKuguASiqhi+qkntHtLf9tzaRowFxZi6O80eBEp6k=","timestampMs":1532723403607,"ctsProfileMatch":false,"apkCertificateDigestSha256":[],"basicIntegrity":false,"advice":"RESTORE_TO_FACTORY_ROM,LOCK_BOOTLOADER"}
			debugLog("JWS payload: " + JSON.stringify(jws.payloadObj));
			
			// we'll just check for the presence of the following required keys. If any are missing, we'll fail
			var requiredKeys = [ "nonce", "ctsProfileMatch", "basicIntegrity", "timestampMs" ];
			var payloadKeys = Object.keys(jws.payloadObj);
			for (var i = 0; i < requiredKeys.length && valid; i++) {
				if (payloadKeys.indexOf(requiredKeys[i]) < 0) {
					valid = false;
					result["error"] = "JWS payload missing required key: " + requiredKeys[i];
				}
			}
		}
		
		// Verify that the nonce in the response is identical to the concatenation of authenticatorData and clientDataHash.
		if (valid) {
			var nonce = jws.payloadObj["nonce"];
			var verificationData = unpackedAuthData["rawBytes"].concat(clientDataHashBytes);
			var verificationDataHash = hextob64(BAtohex(sha256(verificationData)));
			
			if (nonce == null || nonce.length <= 0 || verificationDataHash == null || !(nonce == verificationDataHash)) {
				valid = false;
				result["error"] = "The nonce in the JWS did not match the hash of the concatenation of authData and clientDataHash";
			}
		}
				
		// Verify that the attestation certificate is issued to the hostname "attest.android.com" (see SafetyNet online documentation).
		if (valid) {
			var x509Cert = new X509();
			x509Cert.readCertPEM(certToPEM(x5c[0]));
			var subjectPieces = unpackSubjectDN(x509Cert.getSubjectString());
			if (!("CN" in subjectPieces && subjectPieces["CN"] == "attest.android.com")) {
				valid = false;
				result["error"] = "The attestation certificate was not issued to the hostname attest.android.com";
			}
		}		
		
		// Verify that the ctsProfileMatch attribute in the payload of response is true.
		if (valid) {
			var ctsProfileMatch = jws.payloadObj["ctsProfileMatch"];
			if (ctsProfileMatch == null || !ctsProfileMatch) {
				valid = false;
				result["error"] = "The ctsProfileMatch attribute in the JWS payload was not true";
			}
		}
		
		// this extra check is not in the webauthn spec, but is good practice
		
		// check that timestampMs is no older than one minute, and also not in the future
		if (valid) {
			var now = (new Date()).getTime();
			if (jws.payloadObj["timestampMs"] > now) {
				valid = false;
				result["error"] = "The timestampMs in the JWS payload is in the future";
			}
			
			if (valid) {
				if (GLOBALPOLICY.androidSafetyNetMaxAttestationAgeMS >= 0 && jws.payloadObj["timestampMs"] < (now-GLOBALPOLICY.androidSafetyNetMaxAttestationAgeMS)) {	
					valid = false;
					result["error"] = "The timestampMs in the JWS payload is too old";
				}
			}
		}
		
		// If successful, return attestation type Basic with the attestation trust path set to the above attestation certificate.
		if (valid) {
			// done!
			result["success"] = true;
			result["attestationType"] = "Basic";
			result["attestationTrustPath"] = x5c;
			result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
			result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
			result["credentialPublicKey"] = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
			result["format"] = attestationObject["fmt"];
			result["error"] = null;
		}

		debugLog("validateAttestationStatementAndroidSafetyNet exit: " + JSON.stringify(result));
		return result;
	}
	
	function checkType(asn1, type) {
		if (asn1.typeName() != type) {
			throw ("ASN1 error. Expected: " + type + " Found: " + asn1.typeName());
		}
	}

	function parseInteger(asn1) {
		// check that this is an integer
		checkType(asn1, "INTEGER");
		return parseInt(asn1.stream.hexDump(asn1.posContent(), asn1.posEnd(), true), 16);
	}

	function parseSetOfInteger(asn1) {
		// check that this is a set
		checkType(asn1, "SET");
		var result = [];
		if (asn1.sub != null && Array.isArray(asn1.sub)) {
			for (var i = 0; i < asn1.sub.length; i++) {
				result.push(parseInteger(asn1.sub[i]));
			}
		}
		return result;
	}

	function parseBoolean(asn1) {
		// check that this is a BOOLEAN
		checkType(asn1, "BOOLEAN");
		return (parseInt(asn1.stream.hexDump(asn1.posContent(), asn1.posEnd(), true), 16) != 0);
	}

	function parseNull(asn1) {
		// check that this is a NULL
		checkType(asn1, "NULL");
		return true;
	}

	function parseOctetString(asn1) {
		// check that this is a OCTET_STRING
		checkType(asn1, "OCTET_STRING");
		return b64toBA(hextob64(asn1.stream.hexDump(asn1.posContent(), asn1.posEnd(), true)));
	}

	function parseRootOfTrust(asn1) {
		result = {};

		/*
			RootOfTrust ::= SEQUENCE {
			  verifiedBootKey            OCTET_STRING,
			  deviceLocked               BOOLEAN,
			  verifiedBootState          VerifiedBootState,
			}
		*/
		checkType(asn1, "SEQUENCE");
		if (asn1["sub"] != null && asn1["sub"].length == 3) {
			result["verifiedBootKey"] = parseOctetString(asn1.sub[0]);
			result["deviceLocked"] = parseBoolean(asn1.sub[1]);
			result["verifiedBootKey"] = parseVerifiedBootState(asn1.sub[2]);
		} else {
			throw ("ASN1 error parsing RootOfTrust. Expected sequence length 3. Actual: " + asn1["sub"].length);
		}

	}

	function parseVerifiedBootState(asn1) {
		checkType(asn1, "ENUMERATED");
		var enumMap = {
			"0": "Verified",
			"1": "SelfSigned",
			"2": "Unverified",
			"3": "Failed"
		}
		return enumMap[''+parseInt(asn1.stream.hexDump(asn1.posContent(), asn1.posEnd(), true), 16)];
	}

	function parseSecurityLevel(asn1) {
		checkType(asn1, "ENUMERATED");
		var enumMap = {
			"0": "Software",
			"1": "TrustedEnvironment"
		}
		return enumMap[''+parseInt(asn1.stream.hexDump(asn1.posContent(), asn1.posEnd(), true), 16)];
	}

	function parseAuthorizationList(asn1) {
		result = {};

		/*
			AuthorizationList ::= SEQUENCE {
			  purpose                    [1] EXPLICIT SET OF INTEGER OPTIONAL,
			  algorithm                  [2] EXPLICIT INTEGER OPTIONAL,
			  keySize                    [3] EXPLICIT INTEGER OPTIONAL,
			  digest                     [5] EXPLICIT SET OF INTEGER OPTIONAL,
			  padding                    [6] EXPLICIT SET OF INTEGER OPTIONAL,
			  ecCurve                    [10] EXPLICIT INTEGER OPTIONAL,
			  rsaPublicExponent          [200] EXPLICIT INTEGER OPTIONAL,
			  activeDateTime             [400] EXPLICIT INTEGER OPTIONAL
			  originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL
			  usageExpireDateTime        [402] EXPLICIT INTEGER OPTIONAL
			  noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
			  userAuthType               [504] EXPLICIT INTEGER OPTIONAL,
			  authTimeout                [505] EXPLICIT INTEGER OPTIONAL,
			  allowWhileOnBody           [506] EXPLICIT NULL OPTIONAL,
			  allApplications            [600] EXPLICIT NULL OPTIONAL,
			  applicationId              [601] EXPLICIT OCTET_STRING OPTIONAL,
			  creationDateTime           [701] EXPLICIT INTEGER OPTIONAL,
			  origin                     [702] EXPLICIT INTEGER OPTIONAL,
			  rollbackResistant          [703] EXPLICIT NULL OPTIONAL,
			  rootOfTrust                [704] EXPLICIT RootOfTrust OPTIONAL,
			  osVersion                  [705] EXPLICIT INTEGER OPTIONAL,
			  osPatchLevel               [706] EXPLICIT INTEGER OPTIONAL,
			  attestationApplicationId   [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdBrand         [710] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdDevice        [711] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdProduct       [712] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdSerial        [713] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdImei          [714] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdMeid          [715] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			  attestationIdModel         [717] EXPLICIT OCTET_STRING OPTIONAL, # KM3
			}	
		*/

		var tagMap = {
			"[1]": { "tag": "purpose", "func": parseSetOfInteger },
			"[2]": { "tag": "algorithm", "func": parseInteger },
			"[3]": { "tag": "keySize", "func": parseInteger },
			"[5]": { "tag": "digest", "func": parseSetOfInteger },
			"[6]": { "tag": "padding", "func": parseSetOfInteger },
			"[10]": { "tag": "ecCurve", "func": parseInteger },
			"[200]": { "tag": "rsaPublicExponent", "func": parseInteger },
			"[400]": { "tag": "activeDateTime", "func": parseInteger },
			"[401]": { "tag": "originationExpireDateTime", "func": parseInteger },
			"[402]": { "tag": "usageExpireDateTime", "func": parseInteger },
			"[503]": { "tag": "noAuthRequired", "func": parseNull },
			"[504]": { "tag": "userAuthType", "func": parseInteger },
			"[505]": { "tag": "authTimeout", "func": parseInteger },
			"[506]": { "tag": "allowWhileOnBody", "func": parseNull },
			"[600]": { "tag": "allApplications", "func": parseNull },
			"[601]": { "tag": "applicationId", "func": parseOctetString },
			"[701]": { "tag": "creationDateTime", "func": parseInteger },
			"[702]": { "tag": "origin", "func": parseInteger },
			"[703]": { "tag": "rollbackResistant", "func": parseNull },
			"[704]": { "tag": "rootOfTrust", "func": parseRootOfTrust },
			"[705]": { "tag": "osVersion", "func": parseInteger },
			"[706]": { "tag": "osPatchLevel", "func": parseInteger },
			"[709]": { "tag": "attestationApplicationId", "func": parseOctetString },
			"[710]": { "tag": "attestationIdBrand", "func": parseOctetString },
			"[711]": { "tag": "attestationIdDevice", "func": parseOctetString },
			"[712]": { "tag": "attestationIdProduct", "func": parseOctetString },
			"[713]": { "tag": "attestationIdSerial", "func": parseOctetString },
			"[714]": { "tag": "attestationIdImei", "func": parseOctetString },
			"[715]": { "tag": "attestationIdMeid", "func": parseOctetString },
			"[716]": { "tag": "attestationIdManufacturer", "func": parseOctetString },
			"[717]": { "tag": "attestationIdModel", "func": parseOctetString }
		};

		checkType(asn1, "SEQUENCE");

		for (var i = 0; i < asn1.sub.length; i++) {
			// what explicit type is this?
			var typeName = asn1.sub[i].typeName();
			// call the type-specific parsing function
			debugLog("Processing attribute list explicit type: " + typeName);
			if (tagMap[typeName] != null) {
				result[tagMap[typeName].tag] = tagMap[typeName].func(asn1.sub[i].sub[0]);
			} else {
				throw ("ASN1 error parsing AttributeList. Received unknown explicit type: " + typeName);
			}
		}

		return result;
	}

	/**
	 * Parses the oid extension value to determine attestation extension
	 * @param hexstr of the tlv of the extension
	 */
	function parseAndroidKeyAttestation(tlv) {

		var result = {};

		// tlv should be hex string TLV asn1 sequence of KeyDescription
		var asn1 = ASN1.decode(b64toBA(hextob64(tlv)));

		// there should be 8
		/*
		KeyDescription ::= SEQUENCE {
		  attestationVersion         INTEGER, # KM2 value is 1. KM3 value is 2.
		  attestationSecurityLevel   SecurityLevel,
		  keymasterVersion           INTEGER,
		  keymasterSecurityLevel     SecurityLevel,
		  attestationChallenge       OCTET_STRING,
		  uniqueId                   OCTET_STRING,
		  softwareEnforced           AuthorizationList,
		  teeEnforced                AuthorizationList,
		}
		*/

		if (asn1["sub"] != null && asn1["sub"].length == 8) {
			// 1 = KM2, 2 = KM3
			result["attestationVersion"] = parseInteger(asn1.sub[0]);

			// 0 = software, 1 = trusted environment
			result["attestationSecurityLevel"] = parseSecurityLevel(asn1.sub[1]);

			// not sure what this value means
			result["keymasterVersion"] = parseInteger(asn1.sub[2]);

			// 0 = software, 1 = trusted environment
			result["keymasterSecurityLevel"] = parseSecurityLevel(asn1.sub[3]);

			// octet string
			result["attestationChallenge"] = parseOctetString(asn1.sub[4]);

			// octet string
			result["uniqueId"] = parseOctetString(asn1.sub[5]);

			// Authorization List
			result["softwareEnforced"] = parseAuthorizationList(asn1.sub[6]);

			// Authorization List
			result["teeEnforced"] = parseAuthorizationList(asn1.sub[7]);
		}
		return result;
	}
		
	function validateAttestationStatementAndroidKey(attestationObject, unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementAndroidKey enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};
	
		// see https://www.w3.org/TR/webauthn/#android-key-attestation
		var valid = true;
		
		// check attestation statement is present
		var attStmt = attestationObject["attStmt"];
		if (attStmt == null) {
			valid = false;
			result["error"] = "attStmt missing from attestationObject";
		}
		
		// get the alg
		var alg = null;
		if (valid) {
			alg = attStmt["alg"];
			if (alg == null) {
				valid = false;
				result["error"] = "Missing alg in attestation statement";	
			}
			debugLog("Android Key attestation statement alg: " + alg);
		}
		
		var sig = null;
		if (valid) {
			// get sig as byte array
			sig = (attStmt["sig"] != null ? bytesFromArray(attStmt["sig"],
					0, -1) : null);
			if (sig == null) {
				valid = false;
				result["error"] = "Missing sig in attestation statement";
			}
		}
		
		var x5c = [];
		if (valid) {
			// get x5c
			if (attStmt["x5c"] != null && Array.isArray(attStmt["x5c"])) {
				for (var i = 0; i < attStmt["x5c"].length; i++) {
					x5c.push(bytesFromArray(attStmt["x5c"][i], 0, -1));
				}
			}
			
			if (x5c.length <= 0) {
				valid = false;
				result["error"] = "Missing x5c in attestation statement";
			}
		}
		
		// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.
		if (valid) {
			if (alg == -7) {
				var verificationData = unpackedAuthData["rawBytes"].concat(clientDataHashBytes);
				if (verifyFIDOSignature(verificationData, x5c[0], sig, alg)) {
					debugLog("Signature check OK!");
				} else {
					valid = false;
					result["error"] = "Signature validation failed";
				}
			} else {
				// signature algorithm not supported by this implementation
				valid = false;
				result["error"] = "Attestation signature type: " + alg + " not yet supported";
			}
		}

		// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
		var attestationCertPEM = null;
		if (valid) {
			attestationCertPEM = certToPEM(x5c[0]);
			var attestationCert = new X509();
			attestationCert.readCertPEM(attestationCertPEM);
			var certPublicKey = attestationCert.getPublicKey();
			var attestedPublicKey = coseKeyToPublicKey(unpackedAuthData["attestedCredData"]["credentialPublicKey"]);
			
			// are these keys the same, and not null?
			if (!(certPublicKey != null && certPublicKey["pubKeyHex"] != null && 
					attestedPublicKey != null && attestedPublicKey["pubKeyHex"] &&
					certPublicKey["pubKeyHex"] == attestedPublicKey["pubKeyHex"])) {
				valid = false;
				result["error"] = "Public key in the first certificate in x5c does not match the credentialPublicKey in the attestedCredentialData";
			}
		}
		
		// Verify that in the attestation certificate extension data....
		var androidKeyAttestation = null;
		if (valid) {
			//
			// get and parse the attestation extension represented by oid 1.3.6.1.4.1.11129.2.1.17
			//
			var x509Cert = new X509();
			x509Cert.readCertPEM(attestationCertPEM);
			var oidInfo = x509Cert.getExtInfo("1.3.6.1.4.1.11129.2.1.17");
			if (oidInfo == null) {
				valid = false;
				result["error"] = "Android-key attestation certificate missing extension 1.3.6.1.4.1.11129.2.1.17";
			}

			if (valid) {
				var tlv = ASN1HEX.getTLV(pemtohex(attestationCertPEM), oidInfo.vidx);
				
				androidKeyAttestation = parseAndroidKeyAttestation(tlv);
				if (androidKeyAttestation == null) {
					valid = false;
					result["error"] = "Unable to parse android-key attestation certificate extension 1.3.6.1.4.1.11129.2.1.17";
				}
			}
		}
		
		
		// The value of the attestationChallenge field is identical to clientDataHash
		if (valid) {
			debugLog("androidKeyAttestation: " + JSON.stringify(androidKeyAttestation));
			if (androidKeyAttestation["attestationChallenge"] != null && androidKeyAttestation["attestationChallenge"].length > 0) {
				if (!baEqual(androidKeyAttestation["attestationChallenge"] , clientDataHashBytes)) {
					valid = false;
					result["error"] = "androidKeyAttestation attestationChallenge did not match clientDataHash";					
				}
			} else {
				valid = false;
				result["error"] = "Missing attestationChallenge in androidKeyAttestation";
			}
		}

		// The AuthorizationList.allApplications field is not present, since PublicKeyCredential must be bound to the RP ID.
		if (valid) {
			if (androidKeyAttestation["allApplications"] != null) {
				valid = false;
				result["error"] = "AuthorizationList.allApplications found in androidKeyAttestation when it should not be present";
			}
		}
		
		// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
		// which AuthorizationList? See https://github.com/w3c/webauthn/issues/1022
		// for now I'll go with teeEnforced. It may be that you are supposed to check
		// metadata, similar to rules from UAF:
		// https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-reg-v1.2-rd-20171128.html
		// 
		if (valid) {
			// Found a definition of KM_ORIGIN_GENERATED at:
			// https://github.com/NuclearAndroidProject1/android_hardware_libhardware/blob/master/include/hardware/keymaster_defs.h
			// There the value is 0
			var authzListOrigin = null;
			if (androidKeyAttestation["teeEnforced"] != null) {
				authzListOrigin = androidKeyAttestation["teeEnforced"]["origin"];
			}
		
			// if still null, fallback to softwareEnforced
			if (authzListOrigin == null && androidKeyAttestation["softwareEnforced"] != null) {
				authzListOrigin = androidKeyAttestation["softwareEnforced"]["origin"];
			}
		
			// assuming KM_ORIGIN_GENERATED == 0
			if (authzListOrigin == null || authzListOrigin != 0) {
				valid = false;
				result["error"] = "AuthorizationList.orgin was not KM_ORIGIN_GENERATED. Value: " + authzListOrigin;
			}
		}
		
		// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
		if (valid) {
			// found values here https://github.com/NuclearAndroidProject1/android_hardware_libhardware/blob/master/include/hardware/keymaster_defs.h
			var authzListPurpose = null;
			if (androidKeyAttestation["teeEnforced"] != null) {
				authzListPurpose = androidKeyAttestation["teeEnforced"]["purpose"];
			}
		
			// if still null, fallback to softwareEnforced
			if (authzListPurpose == null && androidKeyAttestation["softwareEnforced"] != null) {
				authzListPurpose = androidKeyAttestation["softwareEnforced"]["purpose"];
			}
		
			// KM_PURPOSE_SIGN == 2. Note that it is a set of integer, so will be returned as JSON array
			if (authzListPurpose == null || !Array.isArray(authzListPurpose)) {
				valid = false;
				result["error"] = "AuthorizationList.purpose was not present.";
			} else {
				if (authzListPurpose.indexOf(2) < 0) {
					valid = false;
					result["error"] = "AuthorizationList.purpose did not contain KM_PURPOSE_SIGN. Value: " + JSON.stringify(authzListPurpose);
				}
			}
		}

		// If successful, return attestation type Basic with the attestation trust path set to the above attestation certificate.
		if (valid) {
			// done!
			result["success"] = true;
			result["attestationType"] = "Basic";
			result["attestationTrustPath"] = x5c;
			result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
			result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
			result["credentialPublicKey"] = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
			result["format"] = attestationObject["fmt"];
			result["error"] = null;
		}

		debugLog("validateAttestationStatementAndroidKey exit: " + JSON.stringify(result));
		return result;
	}

	function parseAppleOIDExtension(asn1) {
		let result = {};

		/*
		 * OID 1.2.840.113635.100.8.2 ::= SEQUENCE { nonce [1] EXPLICIT OCTET_STRING  }
		 */

		let tagMap = {
			"[1]" : {
				"tag" : "nonce",
				"func" : parseOctetString
			}
		};

		checkType(asn1, "SEQUENCE");

		for (let i = 0; i < asn1.sub.length; i++) {
			// what explicit type is this?
			let typeName = asn1.sub[i].typeName();
			// call the type-specific parsing function
			debugLog("Processing attribute list explicit type: " + typeName);
			if (tagMap[typeName] != null) {
				result[tagMap[typeName].tag] = tagMap[typeName]
						.func(asn1.sub[i].sub[0]);
			} else {
				throw ("ASN1 error in parseAppleOIDExtension. Received unknown explicit type: " + typeName);
			}
		}

		return result;
	}

	function validateAttestationStatementApple(attestationObject,
			unpackedAuthData, clientDataHashBytes) {
		debugLog("validateAttestationStatementApple enter");
		let result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};

		// see https://www.w3.org/TR/webauthn/#TBD
		let valid = true;

		// check attestation statement is present
		let attStmt = attestationObject["attStmt"];
		if (attStmt == null) {
			valid = false;
			result["error"] = "attStmt missing from attestationObject";
		}

		let x5c = [];
		let attestationCertPEM = null;
		if (valid) {
			// get x5c
			if (attStmt["x5c"] != null && Array.isArray(attStmt["x5c"])) {
				for (var i = 0; i < attStmt["x5c"].length; i++) {
					x5c.push(bytesFromArray(attStmt["x5c"][i], 0, -1));
				}
			}

			if (x5c.length <= 0) {
				valid = false;
				result["error"] = "Missing x5c in attestation statement";
			}

			attestationCertPEM = certToPEM(x5c[0]);
		}

		// Verification based on https://github.com/w3c/webauthn/pull/1491

		// build the nonce - which is sha256(authData + clientDataHash)
		let verificationDataHash = sha256(unpackedAuthData["rawBytes"].concat(clientDataHashBytes));

		// Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1 sequence. 
		// Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.		
		let oidInfo = null;
		if (valid) {
			debugLog("Checking attestation cert OID extension 1.2.840.113635.100.8.2....");
			//
			// get and parse the attestation extension represented by oid
			// 1.2.840.113635.100.8.2
			//
			let x509Cert = new X509();
			x509Cert.readCertPEM(attestationCertPEM);

			debugLog("About to call x509Cert.getExtInfo");
			oidInfo = x509Cert.getExtInfo("1.2.840.113635.100.8.2");

			if (oidInfo == null) {
				valid = false;
				result["error"] = "Apple attestation certificate did not contain extension with oid: 1.2.840.113635.100.8.2";
			}
		}
		
		let tlv = null;
		if (valid) {
			debugLog("About to call ASN1HEX.getTLV");
			tlv = ASN1HEX.getTLV(pemtohex(attestationCertPEM), oidInfo.vidx);
			if (tlv == null) {
				valid = false;
				result["error"] = "Unable to parse certificate extension with oid: 1.2.840.113635.100.8.2";
			}
		}
		
		let oidResult = null;
		if (valid) {
			// tlv should be a SEQUENCE, with 1 tagged element which is an OCTET-STRING
			debugLog("About to call ASN1.decode on hex tlv: " + tlv);
			let asn1 = ASN1.decode(b64toBA(hextob64(tlv)));	
			
			if (asn1 == null || asn1["sub"] == null || !asn1["sub"].length == 1) {
				valid = false;
				result["error"] = "Invalid asn1 structure of attestation certificate oid: 1.2.840.113635.100.8.2";
			}
			
			if (valid) {
				oidResult = parseAppleOIDExtension(asn1);
				
				if (oidResult == null || oidResult["nonce"] == null) {
					valid = false;
					result["error"] = "Invalid fields in attestation certificate oid: 1.2.840.113635.100.8.2";
				}
			}
		}
			
		if (valid) {
			// compare the oid extension octet string with the verification data hash
			if (!baEqual(oidResult.nonce, verificationDataHash)) {
				valid = false;
				result["error"] = "The octet string in certificate oid: 1.2.840.113635.100.8.2 did not match the verification data hash";
			}
		}

		// Verify that the public key in the first certificate in x5c matches the
		// credentialPublicKey in the attestedCredentialData in authenticatorData.
		if (valid) {
			debugLog("Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
			let attestationCert = new X509();
			attestationCert.readCertPEM(attestationCertPEM);
			let certPublicKey = attestationCert.getPublicKey();
			let attestedPublicKey = coseKeyToPublicKey(unpackedAuthData["attestedCredData"]["credentialPublicKey"]);

			// are these keys the same, and not null?
			if (!(certPublicKey != null && certPublicKey["pubKeyHex"] != null
					&& attestedPublicKey != null && attestedPublicKey["pubKeyHex"] && certPublicKey["pubKeyHex"] == attestedPublicKey["pubKeyHex"])) {
				valid = false;
				result["error"] = "Public key in the first certificate in x5c does not match the credentialPublicKey in the attestedCredentialData";
			}
		}

		// If successful, return attestation type Basic with the attestation trust
		// path set to the above attestation certificate.
		if (valid) {
			// done!
			result["success"] = true;
			result["attestationType"] = "Basic";
			result["attestationTrustPath"] = x5c;
			result["aaguid"] = unpackedAuthData["attestedCredData"]["aaguid"];
			result["credentialId"] = unpackedAuthData["attestedCredData"]["credentialId"];
			result["credentialPublicKey"] = unpackedAuthData["attestedCredData"]["credentialPublicKey"];
			result["format"] = attestationObject["fmt"];
			result["error"] = null;
		}

		debugLog("validateAttestationStatementApple exit: "
				+ JSON.stringify(result));
		return result;
	}

	/**
	 * Validates the attestation statement
	 * 
	 * @param attestationObject
	 */
	function validateAttestationStatement(attestationObject, unpackedAuthData,
			clientDataHashBytes) {
		debugLog("validateAttestationStatement enter");
		var result = {
			"success" : false,
			"attestationType" : null,
			"attestationTrustPath" : null,
			"aaguid" : null,
			"error" : "Unknown Error validating Attestation Statement"
		};
		if (attestationObject["fmt"] == "fido-u2f") {
			result = validateAttestationStatementFIDOU2F(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "packed") {
			result = validateAttestationStatementPacked(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "none") {
			result = validateAttestationStatementNone(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "tpm") {
			result = validateAttestationStatementTPM(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "android-safetynet") {
			result = validateAttestationStatementAndroidSafetyNet(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "android-key") {
			result = validateAttestationStatementAndroidKey(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else if (attestationObject["fmt"] == "apple") {
			result = validateAttestationStatementApple(attestationObject,
					unpackedAuthData, clientDataHashBytes);
		} else {
			result["error"] = "No implementation yet for validation of attestation format: "
					+ attestationObject["fmt"];
		}
		debugLog("validateAttestationStatement exit: " + JSON.stringify(result));
		return result;
	}


	// export our functions in a container object
	global.fidotools = {
		sha256: sha256,
		bytesFromArray: bytesFromArray,
		bytesToUInt32BE: bytesToUInt32BE,
		unpackAuthData: unpackAuthData,
		validateAttestationStatement: validateAttestationStatement,
		aaguidBytesToUUID: aaguidBytesToUUID,
		coseKeyToPublicKey: coseKeyToPublicKey,
		publicKeyToCOSEKey: publicKeyToCOSEKey,
		certToPEM: certToPEM,
		verifyFIDOSignature: verifyFIDOSignature
	}
})(this);
