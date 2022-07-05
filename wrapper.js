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
    console.debug('Create Response:', response)
    return response
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
            assertion.response.authenticatorData && 
            assertion.response.clientDataJSON && 
            assertion.response.signature)){
                throw new Error('Invalid assertion: ', assertion)
            }
        let assertionJson = {
            type: assertion.type,
            id: assertion.id,
            rawId: await arrayBufferToBase64(assertion.rawId),
            response:{
                authenticatorData: await arrayBufferToBase64(assertion.response.authenticatorData),
                clientDataJSON: await arrayBufferToBase64(assertion.response.clientDataJSON),
                signature: await arrayBufferToBase64(assertion.response.signature),
                userHandle: await arrayBufferToBase64(assertion.response.userHandle)
            }
        }
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


