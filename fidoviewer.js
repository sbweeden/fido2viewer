function htmlEncode(value) {
    if (value) {
    	return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    } else {
        return '';
    }
}

function showDiv(id) {
	$('#'+id).show();
}

function hideDiv(id) {
	$('#'+id).hide();
}

function toggleDiv(id) {
	$('#'+id).toggle();
}


function updateMsgRaw(msg) {
	$('#detailsDiv').html(msg);
	showDiv("detailsDiv");
}

function updateMsg(msg) {
	updateMsgRaw(htmlEncode(msg));
}

function appendMsgRaw(msg) {
	$('#detailsDiv').append('<br />' + msg);
}

function appendMsg(msg) {
	appendMsgRaw(htmlEncode(msg).replace(/(?:\r\n|\r|\n)/g, '<br>'));
}

function clearMsg() {
	hideDiv("detailsDiv");
	$('#detailsMsgDiv').innerHTML = "";
}

function getPEMInfo(pemCert) {
	var cert = new X509();
	cert.readCertPEM(pemCert);
	return cert.getInfo().replace(/(?:\r\n|\r|\n)/g, '<br>');
}

function getYubicoDescriptionTable(yubicoMetadata) {
	var result = '<table border=1>' + 
	'<tr><th>Description</th><th>Icon</th><th>Product Link</th></tr>';

	yubicoMetadata.devices.forEach((d) => {
		result += '<tr>' +
			'<td>' + d.displayName + '</td>' + 
			'<td><img src="' + d.imageUrl + '" style="max-height: 50px; max-width: 100px;" /></td>' +
			'<td><a href="' + d.deviceUrl + '">' + d.deviceUrl + '</a></td>' +
			'</tr>';
	});

	result += '</table>';
	return result;
}

function populateMetadataTable() {
	// delete any existing data table rows
	$('metadataTable').find("tr:gt(0)").remove();

	fidotools.allMetadata.forEach((e) => {
		console.log("Processing entry: " + e.label);
		$('#metadataTable')
			.append('<tr>' +
				'<td>' + e.label + '</td>' +
				'<td>' + (e.type == "FIDO2_METADATA" ? e.value.description : 
					(e.type == "PEM_CERT") ? getPEMInfo(e.value) : 
						(e.type == "YUBICO" ? getYubicoDescriptionTable(e.value) : '')) + '</td>' + 
				'<td>' + (e.type == "FIDO2_METADATA" ? '<img src="' + e.value.icon + '" style="max-height: 50px; max-width: 100px;" />' : 
					(e.type == "PEM_CERT" ? '' : 
						(e.type == "YUBICO" ? '<img src="' + e.value.vendorInfo.imageUrl + '" style="max-height: 50px; max-width: 100px;" />' : 
							''))) + '</td>' +
				'<td>' + e.type + '</td>'
			);
	});
}

function populateTestAttestationSelect() {
	var selectHTML = 'Test data set:&nbsp;<select id="testAttestationIndex" name="testAttestationIndex">';
	for (var i = 0; i < testAttestationData.length; i++) {
		selectHTML += '<option value="' + i + '">' + testAttestationData[i].label + '</option>';
	}
	selectHTML += '</select>';
	$('#testAttestationSelectDiv').html(selectHTML);
}

function testAttestation() {
	clearMsg();

	var index = $('#testAttestationIndex').val();
	if (index >= 0 && index < testAttestationData.length) {
	// populate values from testAttestationData
		$('#attestationId').val(testAttestationData[index].value.id);
		$('#attestationRawId').val(testAttestationData[index].value.rawId);
		$('#attestationClientDataJSON').val(testAttestationData[index].value.response.clientDataJSON);
		$('#attestationAttestationObject').val(testAttestationData[index].value.response.attestationObject);
		$('#attestationGetClientExtensionResults').val(
			testAttestationData[index].value.getClientExtensionResults ? JSON.stringify(testAttestationData[index].value.getClientExtensionResults) : '');
	} else {
		updateMsg("Error: Illegal test data set value");
	}
}

function populateTestAssertionSelect() {
	var selectHTML = 'Test data set:&nbsp;<select id="testAssertionIndex" name="testAssertionIndex">';
	for (var i = 0; i < testAssertionData.length; i++) {
		selectHTML += '<option value="' + i + '">' + testAssertionData[i].label + '</option>';
	}
	selectHTML += '</select>';
	$('#testAssertionSelectDiv').html(selectHTML);
}

function testAssertion() {
	clearMsg();

	var index = $('#testAssertionIndex').val();
	if (index >= 0 && index < testAssertionData.length) {
	// populate values from testAssertionData
		$('#assertionId').val(testAssertionData[index].value.id);
		$('#assertionRawId').val(testAssertionData[index].value.rawId);
		$('#assertionClientDataJSON').val(testAssertionData[index].value.response.clientDataJSON);
		$('#assertionAuthenticatorData').val(testAssertionData[index].value.response.authenticatorData);
		$('#assertionSignature').val(testAssertionData[index].value.response.signature);
		$('#assertionUserHandle').val(
			testAssertionData[index].value.response.userHandle ? testAssertionData[index].value.response.userHandle : '');
		$('#assertionGetClientExtensionResults').val(
			testAssertionData[index].value.getClientExtensionResults ? JSON.stringify(testAssertionData[index].value.getClientExtensionResults) : '');

		if (testAssertionData[index].publicKey) {
			$('#assertionCOSEPublicKeyTextArea').val(myJSONStringify(testAssertionData[index].publicKey));
		}

	} else {
		updateMsg("Error: Illegal test data set value");
	}
}

function exceptionToErrorString(e) {
	var errStr = "";
	if ((typeof e) == "object" && !(JSON.stringify(e) == "{}")) {
		errStr = JSON.stringify(e);
	} else {
		errStr = ''+e;
	}
	return errStr;

}


function appendClientDataJSON(s) {
	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';
	try {
		txt = myJSONStringify(JSON.parse(b64utoutf8(s)));
		txt += "\n";
	} catch (e) {
		var errStr = exceptionToErrorString(e);
		txt = "Unable to decode the clientDataJSON: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Client Data JSON</p>' + 
		'<p>For details see: <a href="https://www.w3.org/TR/webauthn/#sec-client-data">https://www.w3.org/TR/webauthn/#sec-client-data</a></p>' +
		'<textarea id="cdjTextArea" class="' + txtAreaClass + '" rows="' + (numLines+1) + '" cols="80" readonly="true">' + 
		txt + 
		'</textarea><br />');			
}

/*
* If the object is only an array of numbers, replace as a tagged string, otherwise beautify
* in the normal manner. This is used by myJSONStringify to beautify everything but int arrays 
* which can be quite long and take up too much vertical space when printed.
*/
function myJSONReplacer(name,val) {
	if (typeof val == "object" && Array.isArray(val)) {
		var allIntArray = true;
		for (var i = 0; i < val.length && allIntArray; i++) {
			if (typeof val[i] != "number") {
				allIntArray = false;
			}
		}
		if (allIntArray) {
			return "BEGIN_ARRAY" + JSON.stringify(val) + "END_ARRAY";
		}
	}
	return val;
}

/*
* Pretty-prints a JSON object, except for integer arrays which are preserved as a single long line
*/
function myJSONStringify(o) {
	return JSON.stringify(o, myJSONReplacer, 2).replace(/\"BEGIN_ARRAY\[/g, "[").replace(/\]END_ARRAY\"/g, "]");
}

/*
* returns true if o's keys are only "0", "1", ... "n"
*/
function integerKeys(o) {
	var result = false;
	if (o != null) {
		var oKeys = Object.keys(o);
		var intArray = [...Array(oKeys.length).keys()];
		var result = true;
		for (var i = 0; i < intArray.length && result; i++) {
			if (oKeys[i] != ''+intArray[i]) {
				result = false;
			}
		}
	}
	return result;
}

/*
* Recursively inspect every element of o and if it is an object which is not already 
* an Array and who's keys are only the numbers from 0...x then assume that object is an
* ArrayBuffer and convert to BA.
*/
function convertArrayBuffersToByteArrays(o) {
	if (o != null) {
		Object.keys(o).forEach((k)=> {
			if (typeof o[k] == "object") {
				if (!Array.isArray(o[k]) && integerKeys(o[k])) {
					o[k] = fidotools.bytesFromArray(o[k], 0, -1);
				} else {
					convertArrayBuffersToByteArrays(o[k]);
				}
			}
		});
	}
	return o;
}

function publicKeyToPEM(pk) {
	var result = "";
	if (pk instanceof RSAKey) {
		result = KEYUTIL.getPEM(pk);
	} else if (pk instanceof KJUR.crypto.ECDSA) {
		result = fidotools.certToPEM(b64toBA(hextob64(pk.pubKeyHex)));
	}
	return result;			
}

/*
* Dumps to details the authenticator data represented by the byte array ba
*/
function appendAuthData(ba) {
	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';

	try {
		txt += "Raw bytes: " + JSON.stringify(ba) + "\n";
		if (ba && ba.length >= 37) {
			var rpidHashBytes = fidotools.bytesFromArray(ba,0,32);
			txt += "RP ID hash:\n  hex: " + BAtohex(rpidHashBytes) + "\n  b64: " + hextob64(BAtohex(rpidHashBytes)) + "\n\n";

			var flags = ba[32];
			var userPresent = ((flags & 0x01) != 0x00);
			var userVerified = ((flags & 0x04) != 0x00);
			var attestedCredentialData = ((flags & 0x40) != 0x00);
			var extensionData = ((flags & 0x80) != 0x00);
			txt += "FLAGS: 0x" + BAtohex([ flags ]) + "\n"
			txt += "  User Present (UP): " + userPresent + "\n";
			txt += "  User Verified (UV): " + userVerified + "\n";
			txt += "  Attested Credential Data (AT): " + attestedCredentialData + "\n";
			txt += "  Extension Data (ED): " + extensionData + "\n";

			var counter = fidotools.bytesToUInt32BE(fidotools.bytesFromArray(ba, 33, 37));
			txt += "\n";
			txt += "counter: " + counter + "\n";

			var nextByte = 37;

			if (attestedCredentialData) {
				txt += "\n\n========================\nAttested Credential Data\n========================\n";
				// are there enough bytes to read AAGUID?
				if (ba.length < (nextByte + 16)) {
					throw "Authenticator data indicated AT present, but not enough bytes to read AAGUID";
				}

				var aaguidBytes = fidotools.bytesFromArray(ba, nextByte, (nextByte+16));
				nextByte += 16;

				txt += "\n";
				txt += "AAGUID: " + fidotools.aaguidBytesToUUID(aaguidBytes) + "\n";

				// are there enough bytes for credentialIdLength?
				if (ba.length < (nextByte + 2)) {
					throw "Authenticator data indicated AT present, but not enough bytes to read credential id length";
				}

				var credentialIdLength = ba[nextByte] * 256 + ba[nextByte+1];
				nextByte += 2;

				txt += "\n";
				txt += "Credential ID Length: " + credentialIdLength + "\n";

				if (credentialIdLength == 0) {
					throw "Authenticator data indicated AT present, but credential id length was 0";
				}

				if (ba.length < (nextByte + credentialIdLength)) {
					throw "Authenticator data indicated AT present, but not enough bytes to satisfy credential id length of: " + credentialIdLength;	
				}

				credentialIdBytes = fidotools.bytesFromArray(ba, nextByte, nextByte + credentialIdLength);
				nextByte += credentialIdLength;

				txt += "\n";
				txt += "Credential ID (note that b64url value is normally the same as id/rawId):\n";
				txt += "  hex: " + BAtohex(credentialIdBytes) + "\n";
				txt += "  b64url: " + hextob64u(BAtohex(credentialIdBytes)) + "\n\n";

				//
				// try CBOR decoding the remaining bytes. 
				// NOTE: There could be both credentialPublicKey and extensions objects
				// so we use this special decodeVariable that Shane wrote to deal with
				// remaining bytes.
				//
				var remainingBytes = fidotools.bytesFromArray(ba, nextByte, -1);
				try {
					var decodeResult = CBOR.decodeVariable((new Uint8Array(remainingBytes)).buffer);
					var credentialPublicKey = decodeResult["decodedObj"];
					convertArrayBuffersToByteArrays(credentialPublicKey);

					nextByte += (decodeResult["offset"] == -1 ? remainingBytes.length : decodeResult["offset"]);

					txt += "\n";
					txt += "Credential Public Key (COSE):\n" + myJSONStringify(credentialPublicKey) + "\n";

					var publicKey = fidotools.coseKeyToPublicKey(credentialPublicKey);
					if (publicKey != null) {
						if (publicKey instanceof RSAKey) {
							txt += "Credential Public Key type: RSA\n";
						} else if (publicKey instanceof KJUR.crypto.ECDSA) {
							txt += "Credential Public Key type: ECDSA\n";
						} else {
							txt += "WARNING: Unable to determine type of public key";
						}
						txt += "Credential Public Key (PEM):\n"
						txt += publicKeyToPEM(publicKey);
					} else {
						txt += "\nWARNING: Unable to convert COSE public key to KJUR public key object\n";
					}

				} catch (e) {
					nextByte = -1;
					var errStr = exceptionToErrorString(e);							
					throw "Unable to CBOR decode credentialPublicKey: " + errStr;
				}
			}

			if (nextByte > 0 && extensionData) {
				txt += "\n\n==========\nExtensions\n==========\n";

				try {
					var extensions = CBOR.decode((new Uint8Array(fidotools.bytesFromArray(ba, nextByte, -1))).buffer);	
					// must have worked
					nextByte = ba.length;
					convertArrayBuffersToByteArrays(extensions);
					txt += "\n" + myJSONStringify(extensions) + "\n";
				} catch (e) {
					var errStr = exceptionToErrorString(e);
					throw "Unable to CBOR decode extensions: " + errStr;
				}
			}

			if (nextByte != ba.length) {
				txt += "\nWARNING: Not all authenticator data bytes were processed successfully. nextByte: " + nextByte + " ba.length: " + ba.length + "\n";		
			}
		} else {
			throw "Authenticator data is not at least 37 bytes long, so it cannot be valid";
		}
	} catch (e) {
		var errStr = exceptionToErrorString(e);
		txt = "Unable to decode the authenticator data: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Decoded Authenticator Data</p>' + 
		'<p>For details see: <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">https://www.w3.org/TR/webauthn/#sec-authenticator-data</a></p>' +
		'<textarea id="authDataTextArea" class="' + txtAreaClass + '" rows="' + (numLines+1	) + '" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');
}

/*
* Dumps to details the attestation statement contained within the attestationObject
*/
function appendAttestationStatement(decodedAttestationObject, clientDataHashBytes) {
	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';

	txt += 'Format: ' + decodedAttestationObject.fmt + '\n';
	var attestationStatementValidationResult = null;
	try {
		var unpackedAuthData = fidotools.unpackAuthData(decodedAttestationObject.authData);
		attestationStatementValidationResult = fidotools.validateAttestationStatement(
			decodedAttestationObject,
			unpackedAuthData,
			clientDataHashBytes == null ? [] : clientDataHashBytes);

		if (attestationStatementValidationResult.success) {
			txt += 'Attestation Type: ' + attestationStatementValidationResult.attestationType + '\n';
			txt += 'Attestation Trust Path: ' + myJSONStringify(attestationStatementValidationResult.attestationTrustPath) + '\n';
		} else {
			throw attestationStatementValidationResult.error;
		}
	} catch (e) {
		var errStr = exceptionToErrorString(e);
		txt += "\n\nError processing the attestation statement: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Decoded Attestation Statement</p>' + 
		'<p>For details see: <a href="https://www.w3.org/TR/webauthn/#defined-attestation-formats">https://www.w3.org/TR/webauthn/#defined-attestation-formats</a></p>' +
		'<textarea id="attestationStatementTextArea" class="' + txtAreaClass + '" rows="' + (numLines+1	) + '" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');

	// If the attestation statement validated and is not "None", add the metadata lookup information
	if (attestationStatementValidationResult != null 
		&& attestationStatementValidationResult.success 
		&& attestationStatementValidationResult.attestationType != "None") {
		appendMetadataLookup(attestationStatementValidationResult);
	}
}

/*
* This is a bit of a hack to reverse-lookup the end-user label view of metadata from the metadata service results
*/
function deriveMetadataSummary(s) {
	var result = null;
	for (var i = 0; i < fidotools.allMetadata.length && result == null; i++) {
		// for a start, they have to be the same type of metadata
		if (s.metadata.type == fidotools.allMetadata[i].type) {
			if (s.metadata.type == "FIDO2_METADATA") {
				// if this metadata AAGUID, must match
				if (s.metadata["aaguid"] != null) {
					if (fidotools.allMetadata[i].value["aaguid"] != null && fidotools.allMetadata[i].value["aaguid"] == s.metadata["aaguid"]) {
						result = fidotools.allMetadata[i].label;
					}
				} else {
					// if this metadata has aki, check if arrays matching
					if (s.metadata["attestationCertificateKeyIdentifiers"] != null 
						&& s.metadata["attestationCertificateKeyIdentifiers"].length > 0
						&& fidotools.allMetadata[i].value["attestationCertificateKeyIdentifiers"] != null 
						&& fidotools.allMetadata[i].value["attestationCertificateKeyIdentifiers"].length > 0
						&& s.metadata["attestationCertificateKeyIdentifiers"].length == fidotools.allMetadata[i].value["attestationCertificateKeyIdentifiers"].length) {
						var matching = true;
						for (var j = 0; j < s.metadata["attestationCertificateKeyIdentifiers"].length && matching; j++) {
							if (s.metadata["attestationCertificateKeyIdentifiers"][j] != fidotools.allMetadata[i].value["attestationCertificateKeyIdentifiers"][j]) {
								matching = false;
							}
						}
						if (matching) {
							result = fidotools.allMetadata[i].label;
						}
					}
				}
			} else if (s.metadata.type == "PEM_CERT") {
				// is this entry's PEM cert the same bytes as the candidate?
				var sCert = new X509();
				sCert.readCertPEM(s.caPEM);
				var aCert = new X509();
				aCert.readCertPEM(fidotools.allMetadata[i].value);
				if (sCert.hex != null && aCert.hex != null && sCert.hex == aCert.hex) {
					result = fidotools.allMetadata[i].label;
				}
			} else if (s.metadata.type == "YUBICO") {
				// special case for yubico metadata - description is contained within
				result = fidotools.allMetadata[i].label + ": " + s.metadata.displayName;
			}
		}
	}

	if (result == null) {
		// shouldn't happen
		result = "UNKNOWN - failed resolving metadata to label";
	}

	return result;
}

/*
* Attempts to match the attestation statement validation result to one of our known metadata files
* and validate the attestation trust path if supplied.
*/
function appendMetadataLookup(attestationStatementValidationResult) {
	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';


	try {
		var possibleMetadata = [];

		// first we do a soft lookup assuming this might be a valid registration
		var lookupReg = {
			"aaguid": null,
			"attTrustPath": [],
		};
		if (attestationStatementValidationResult.aaguid != null && attestationStatementValidationResult.aaguid.length > 0) {
				lookupReg.aaguid = fidotools.aaguidBytesToUUID(attestationStatementValidationResult.aaguid).toUpperCase();
			}
			if (attestationStatementValidationResult.attestationTrustPath != null && attestationStatementValidationResult.attestationTrustPath.length > 0) {
				attestationStatementValidationResult.attestationTrustPath.forEach((c) => {
					lookupReg.attTrustPath.push(fidotools.certToPEM(c));
				});
			}

			var linkedMetadata = fidotools.Fido2MetadataService.findMetadataForRegistration(lookupReg);
			if (linkedMetadata != null) {
				// caPEM field value not important for the summary lookup because this can't be a PEM_CERT entry
				possibleMetadata.push({
					"caPEM": "",
					"metadata": linkedMetadata
				});
			} else {
				// if soft lookup didn't work, at least get a candidate list of signers (e.g. PEM certs)
				possibleMetadata = fidotools.Fido2MetadataService.selectPossibleAttestationSigners(attestationStatementValidationResult);
			}

			if (possibleMetadata == null || possibleMetadata.length == 0) {
				txt += 'No matching metadata found\n';
			} else {
				var summary = [];
				possibleMetadata.forEach((s) => {
					summary.push(deriveMetadataSummary(s));
				});
				txt += 'Number of possible matching metadata: ' + possibleMetadata.length + '\n';
				txt += 'Summary of possible matching metadata:' + myJSONStringify(summary) + '\n';
			}
	} catch (e) {
		var errStr = exceptionToErrorString(e);
		txt += "\n\nError resolving metadata: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Metadata Lookup</p>' + 
		'<textarea id="metadataLookupTextArea" class="' + txtAreaClass + '" rows="' + (numLines+1	) + '" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');
}

/*
* Dumps to details the attestation object represented by the b64url encoded string s.
* The clientDataHashBytes are included if known so that any attestation statement
* signature could be verified.
*/
function appendAttestationObject(s, clientDataHashBytes) {
	// first just try the b64url and CBOR decoding of the attestation object
	var attestationObjectError = false;

	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';
	try {
		var attestationObjectBytes = b64toBA(b64utob64(s));

		var decodedAttestationObject = CBOR.decode((new Uint8Array(attestationObjectBytes)).buffer);

		// this is only done to make pretty-print look nicer
		convertArrayBuffersToByteArrays(decodedAttestationObject);

		txt = myJSONStringify(decodedAttestationObject);
		txt += "\n";
	} catch (e) {
		attestationObjectError = true;
		var errStr = exceptionToErrorString(e);
		txt = "Unable to decode the attestation object: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Decoded Attestation Object</p>' + 
		'<p>For details see: <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">https://www.w3.org/TR/webauthn/#sctn-attestation</a></p>' +
		'<textarea id="attestationObjectTextArea" class="' + txtAreaClass + '" rows="'+(numLines+1)+'" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');

	if (!attestationObjectError) {
		// Show details of the authenticator data
		appendAuthData(decodedAttestationObject.authData);

		// If there is an attestation statement, show it also
		if (decodedAttestationObject["attStmt"] != null) {
			appendAttestationStatement(decodedAttestationObject, clientDataHashBytes);
		}
	}
}

function appendRegistrationResultSummary(s) {
	var txt = '';
	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';
	try {
		txt = myJSONStringify(s);
		txt += "\n";
	} catch (e) {
		var errStr = exceptionToErrorString(e);
		txt = "Unable to build registration summary: " + errStr + "\n";
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	if (!s.valid) {
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Registration Summary</p>' + 
		'<textarea id="registrationSummaryTextArea" class="' + txtAreaClass + '" rows="' + (numLines+1) + '" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');			
}

function appendSignatureCheck(sigBytes, cert, sig, alg) {

	var headingClass = 'dataHeadingSuccess';
	var txtAreaClass = 'dataTextArea';
	var txt = '';

	txt += "Signature Base: " + JSON.stringify(sigBytes) + "\n";
	txt += "Public Key:\n";
	if (Array.isArray(cert)) {
		// assertion X509 bytes
		txt += fidotools.certToPEM(cert);
	} else {
		// assume COSE key format
		var pk = fidotools.coseKeyToPublicKey(cert);
		if (pk != null) {
			txt += publicKeyToPEM(pk);	
		} else {
			txt += "Error: Unable to parse COSE key\n";
		}
	}
	txt += "Signature: " + BAtohex(sig) + "\n";

	var result = false;
	var errStr = null;
	try {
		result = fidotools.verifyFIDOSignature(sigBytes, cert, sig, alg);
	} catch (e) {
		errStr = exceptionToErrorString(e);
	}
	
	txt += "Verified: " + result + "\n";
	if (errStr != null) {
		txt += "Exception during signature verification: " + errStr;
	}

	if (!result) {
		headingClass = 'dataHeadingError';
		txtAreaClass = "dataTextAreaError";				
	}

	numLines = (txt.match(/\n/g) || []).length;

	appendMsgRaw('<p class="'+headingClass+'">Signature Validation Result</p>' + 
		'<textarea id="signatureValidationTextArea" class="' + txtAreaClass + '" rows="'+(numLines+1)+'" cols="150" wrap="off" readonly="true">' + 
		txt + 
		'</textarea><br />');
}

function processAttestation() {
	var attestationResult = {
		"id": $('#attestationId').val(),
		"rawId": $('#attestationRawId').val(),
		"type": $('#attestationType').val(),
		"response": {
			"clientDataJSON": $('#attestationClientDataJSON').val(),
			"attestationObject": $('#attestationAttestationObject').val()
		},
		"getClientExtensionResults": $('#attestationGetClientExtensionResults').val()
	};

	updateMsg('');

	// Add a pretty-print of the client data json
	var clientDataHashBytes = null;
	if (attestationResult.response.clientDataJSON != null && attestationResult.response.clientDataJSON.length > 0) {
		appendClientDataJSON(attestationResult.response.clientDataJSON);
		clientDataHashBytes = fidotools.sha256(b64toBA(b64utob64(attestationResult.response.clientDataJSON)));
	}

	// Add a pretty-print of the attestation object
	if (attestationResult.response.attestationObject != null && attestationResult.response.attestationObject.length > 0) {
		appendAttestationObject(attestationResult.response.attestationObject, clientDataHashBytes);
	}

	// try a complete registration verification process, and display the output
	var registrationResult = fidotools.inspectConformanceToolAttestationResult(attestationResult);
	if (registrationResult != null) {
		convertArrayBuffersToByteArrays(registrationResult);
		appendRegistrationResultSummary(registrationResult);
	}
}

function processAssertion() {
	var assertionResult = {
		"id": $('#assertionId').val(),
		"rawId": $('#assertionRawId').val(),
		"type": $('#assertionType').val(),
		"response": {
			"clientDataJSON": $('#assertionClientDataJSON').val(),
			"authenticatorData": $('#assertionAuthenticatorData').val(),
			"signature": $('#assertionSignature').val(),
			"userHandle": $('#assertionUserHandle').val()
		},
		"getClientExtensionResults": $('#assertionGetClientExtensionResults').val()
	};

	var coseKey = null;
	var coseKeyStr = $('#assertionCOSEPublicKeyTextArea').val();
	if (coseKeyStr != null && coseKeyStr.length > 0) {
		coseKey = JSON.parse(coseKeyStr);
	}


	updateMsg('');

	// Add a pretty-print of the client data json
	if (assertionResult.response.clientDataJSON != null && assertionResult.response.clientDataJSON.length > 0) {
		appendClientDataJSON(assertionResult.response.clientDataJSON);
	}

	// Add a pretty-print of the authenticator data
	if (assertionResult.response.authenticatorData != null && assertionResult.response.authenticatorData.length > 0) {
		appendAuthData(b64toBA(b64utob64(assertionResult.response.authenticatorData)));
	}

	// If we have required fields, do a signature check
	if (assertionResult.response.clientDataJSON != null 
		&& assertionResult.response.clientDataJSON.length > 0
		&& assertionResult.response.authenticatorData != null 
		&& assertionResult.response.authenticatorData.length > 0
		&& assertionResult.response.signature != null 
		&& assertionResult.response.signature.length > 0
		&& coseKey != null) {
		var sigBytes = b64toBA(b64utob64(assertionResult.response.authenticatorData)).concat(
			fidotools.sha256(b64toBA(b64utob64(assertionResult.response.clientDataJSON))));
		appendSignatureCheck(
			sigBytes, 
			coseKey,
			b64toBA(b64utob64(assertionResult.response.signature)),
			coseKey["3"]);
	}
}

function onLoad() {
	var selectHTML = 'Test data set:&nbsp;<select id="testAttestationIndex" name="testAttestationIndex">';
	for (var i = 0; i < testAttestationData.length; i++) {
		selectHTML += '<option value="' + i + '">' + testAttestationData[i].label + '</option>';
	}
	selectHTML += '</select>';
	$('#testAttestationSelectDiv').html(selectHTML);

	var selectHTML = 'Test data set:&nbsp;<select id="testAssertionIndex" name="testAssertionIndex">';
	for (var i = 0; i < testAssertionData.length; i++) {
		selectHTML += '<option value="' + i + '">' + testAssertionData[i].label + '</option>';
	}
	selectHTML += '</select>';
	$('#testAssertionSelectDiv').html(selectHTML);

	// metadata
	populateMetadataTable();
}
