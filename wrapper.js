console.debug('navigator.credentials.get wrapper')

let WAD = {
    lastGetRequest: null,
    lastGetResponse: null, 
    lastCreateRequest: null, 
    lastCreateResponse: null,
    base64ToArrayBuffer: function (base64) {
        if(!base64){
            return null
        }
        var binary_string = atob(base64);
        var len = binary_string.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    },
    arrayBufferToBase64: async function (arrayBuff) {
        if(!arrayBuff){
            return null
        }
        var reader = new FileReader()
        return  new Promise(resolve => {
            if (!arrayBuff){
                resolve(null)
            }
            reader.onload = function() {
                var dataUrl = reader.result
                var base64 = dataUrl.split(',')[1]
                resolve(base64);
          }
          reader.readAsDataURL(new Blob([arrayBuff]));
        });
    },
    deserializeAssertion: function (assertion){
        deserializeAssertion(assertion)
    },
    serializeAssertion: async function (assertion){
        try{
            if (!(
                assertion.type &&
                assertion.id &&
                assertion.rawId &&
                assertion.response &&
                assertion.response.clientDataJSON)){
                    throw new Error('Invalid assertion: ', assertion)
                }
            let assertionJson = {
                type: assertion.type,
                id: assertion.id,
                rawId: await arrayBufferToBase64(assertion.rawId),
                response:{
                    clientDataJSON: JSON.parse(base64Decode(assertion.response.clientDataJSON)),
                }
            }
            if (assertion.response.userHandle)
                assertionJson.response.userHandle = await arrayBufferToBase64(assertion.response.userHandle)
            if (assertion.response.authenticatorData) 
                assertionJson.response.authenticatorData = await arrayBufferToBase64(assertion.response.authenticatorData)
            if (assertion.response.attestationObject) 
                assertionJson.response.attestationObject = CBOR.decode(assertion.response.attestationObject)
            return assertionJson
        }catch(e){
            console.debug('Assertion: ', assertion)
            console.error(e)
            return null
        }
    },

    decodeAndPrintAttestationResponse: async function (attestationResponse){
        console.debug("Attestation Response: ", attestationResponse)

        let decodedObject =JSON.parse(JSON.stringify(attestationResponse))
        decodedObject.response.clientDataJSON = JSON.parse(base64Decode(attestationResponse.response.clientDataJSON))
    
        const attestationBuffer = attestationResponse.response.attestationObject
        decodedObject.response.attestationObject = CBOR.decode(attestationBuffer);
        
        const authData = decodedObject.response.attestationObject.authData; 
        let authDataDecoded = {}
        authDataDecoded.rpIdHash = bytesToHex(authData.slice(0, 32));
        authDataDecoded.counter = new DataView(authData.slice(33, 37).buffer).getUint32(0, false); // Big-endian
    
        const flags = authData[32]
        const flagDetails = {
            userPresent: (flags & 0x01) !== 0,  
            userVerified: (flags & 0x04) !== 0,  
            backupElegibility: (flags & 0x18) >> 3, 
            backupState: (flags & 0x20) !== 0,
            attestationDataPesent: (flags & 0x40) !== 0,  
            extensionDataIncluded: (flags & 0x80) !== 0,   
            reserved1: (flags & 0x02) !== 0, 
            reserved2: (flags & 0x38) !== 0, 
        };
        authDataDecoded.flags = flagDetails;
    
        if (flagDetails.attestationDataPesent){
            let attestedCredentialData = {}
    
            attestedCredentialData.aaguid = bytesToHex(authData.slice(37, 37 + 16));
            
            const credentialIdLength = new DataView(authData.slice(53, 53 + 2).buffer).getUint16(0, false); 
            attestedCredentialData.credentialId =  bytesToHex(authData.slice(55, 55 + credentialIdLength));
            
            const credentialPublicKey = CBOR.decode(authData.slice(55 + credentialIdLength).buffer); 
            attestedCredentialData.publicKey = parseCosePublicKey(credentialPublicKey);
    
            authDataDecoded.attestedCredentialData = attestedCredentialData;
        }
    
        decodedObject.response.attestationObject.authData = authDataDecoded
        console.debug("Attestation Response Decoded: ", decodedObject)
    }
} 

let originalNavCredGet=navigator.credentials.get
let originalNavCredCreate=navigator.credentials.create

function swapNavCred(){
    navigator.credentials.get=navCredGetWrapper
    navigator.credentials.create=navCredCreateWrapper
    setTimeout(swapNavCred,500)
}
swapNavCred()

async function navCredGetExecuteAndSwap(webauthnReq){
    navigator.credentials.get = originalNavCredGet
    let promise = navigator.credentials.get(webauthnReq)
    navigator.credentials.get=navCredGetWrapper
    return promise
}

async function navCredCreateExecuteAndSwap(webauthnReq){
    navigator.credentials.create = originalNavCredCreate
    let promise = navigator.credentials.create(webauthnReq)
    navigator.credentials.create=navCredCreateWrapper
    return promise
}

async function navCredGetWrapper(webauthnReq){
    console.debug("Get Request: ", webauthnReq)    
    WAD.lastGetRequest = webauthnReq
    let response = await navCredGetExecuteAndSwap(webauthnReq)
    //let assertionJson = await serializeAssertion(assertion)
    WAD.lastGetResponse = response
    console.debug('Get Response:', response)
    return response
}

async function navCredCreateWrapper(webauthnReq){
    console.debug("Create Request: ", webauthnReq)    
    WAD.lastCreateRequest = webauthnReq
    let response = await navCredCreateExecuteAndSwap(webauthnReq)
    //let assertionJson = await serializeAssertion(assertion)
    WAD.lastCreateResponse = response
    WAD.decodeAndPrintAttestationResponse (response)
    return response
}

function parseCosePublicKey(publicKey) {
    let parsedPublicKey = {};
    parsedPublicKey.keyType = publicKey[1]; // kty (key type)
    parsedPublicKey.algorithm = publicKey[3]; // alg (algorithm)

    if (parsedPublicKey.keyType === 2) { // kty == 2 means EC2 key
        parsedPublicKey.curve = publicKey[-1]; // crv (curve identifier)
        parsedPublicKey.x = publicKey[-2]; // x-coordinate
        parsedPublicKey.y = publicKey[-3]; // y-coordinate
    } else if (parsedPublicKey.keyType === 3) { // RSA Key (kty == 3)
        parsedPublicKey.modulus = publicKey[-1]; // n (modulus)
        parsedPublicKey.exponent = publicKey[-2]; // e (exponent)
    }
    return parsedPublicKey;
}

async function serializeWebauthnRequest(request){
    let jsonRequest = JSON.parse(JSON.stringify(request));
    try{
        if (!(request && request.publicKey && request.publicKey.challenge)){
            throw new Error('Invalid webauthn request')
        }
        jsonRequest.publicKey.challenge = await arrayBufferToBase64(request.publicKey.challenge)
        if (request.publicKey.allowCredentials && Array.isArray(request.publicKey.allowCredentials)){
        for (let i=0; i<request.publicKey.allowCredentials.length; i++){
            jsonRequest.publicKey.allowCredentials[i].id = await arrayBufferToBase64(request.publicKey.allowCredentials[i].id)
        }
        }
        return jsonRequest

    }catch(e){
        console.error(e)
        return null
    }
}

function deserializeWebauthnRequest(request){
    try{
        if (!(request && request.publicKey && request.publicKey.challenge)){
            throw new Error('Invalid webauthn request')
        }
        request.publicKey.challenge = base64ToArrayBuffer(request.publicKey.challenge)
        if (request.publicKey.allowCredentials && Array.isArray(request.publicKey.allowCredentials)){
            for (let i = 0; i < request.publicKey.allowCredentials.length; i++) {
                request.publicKey.allowCredentials[i].id = base64ToArrayBuffer(request.publicKey.allowCredentials[i].id)
            } 
        }
        return request
    }catch(e){
        console.error(e)
        return null
    }
}

async function serializeAssertion(assertion){
    try{
        if (!(
            assertion.type &&
            assertion.id &&
            assertion.rawId &&
            assertion.response &&
            assertion.response.clientDataJSON)){
                throw new Error('Invalid assertion: ', assertion)
            }
        let assertionJson = {
            type: assertion.type,
            id: assertion.id,
            rawId: await arrayBufferToBase64(assertion.rawId),
            response:{
                clientDataJSON: await arrayBufferToBase64(assertion.response.clientDataJSON),
                userHandle: await arrayBufferToBase64(assertion.response.userHandle)
            }
        }
        if (assertion.response.authenticatorData) 
            assertion.authenticatorData = await arrayBufferToBase64(assertion.response.authenticatorData)
        if (assertion.response.attestationObject) 
            assertion.attestationObject = await arrayBufferToBase64(assertion.response.attestationObject)
        return assertionJson
    }catch(e){
        console.debug('Assertion: ', assertion)
        console.error(e)
        return null
    }
}

function deserializeAssertion(assertion){
    try{
        if (!(assertion.type &&
            assertion.id &&
            assertion.rawId &&
            assertion.response &&
            assertion.response.authenticatorData && 
            assertion.response.clientDataJSON && 
            assertion.response.signature)){
                throw new Error('Invalid assertion: ', assertion)
            }
        assertion.response.authenticatorData = base64ToArrayBuffer(assertion.response.authenticatorData)
        assertion.response.clientDataJSON = base64ToArrayBuffer(assertion.response.clientDataJSON)
        assertion.response.signature = base64ToArrayBuffer(assertion.response.signature)
        assertion.response.userHandle = base64ToArrayBuffer(assertion.response.userHandle)
        assertion.rawId = base64ToArrayBuffer(assertion.rawId)

        return assertion
    }catch(e){
        console.error(e)
        return null
    }
}

function base64ToArrayBuffer(base64) {
    if(!base64){
        return null
    }
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

async function arrayBufferToBase64(arrayBuff) {
    if(!arrayBuff){
        return null
    }
    var reader = new FileReader()
    return  new Promise(resolve => {
        if (!arrayBuff){
            resolve(null)
        }
        reader.onload = function() {
            var dataUrl = reader.result
            var base64 = dataUrl.split(',')[1]
            resolve(base64);
      }
      reader.readAsDataURL(new Blob([arrayBuff]));
    });
  }  

function base64Decode(buffer){
    if (buffer)
        return String.fromCharCode.apply(null, new Uint8Array(buffer))
        .replace(/\+/g, '-') // Convert '+' to '-'
        .replace(/\//g, '_') // Convert '/' to '_'
        .replace(/=+$/, ''); // Remove ending '='
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}