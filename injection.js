const script = document.createElement('script')
script.setAttribute("src", chrome.runtime.getURL('wrapper.js'));
(document.head || document.body || document.documentElement || document).appendChild(script)

const script2 = document.createElement('script')
script2.setAttribute("src", chrome.runtime.getURL('cbor.js'));
(document.head || document.body || document.documentElement || document).appendChild(script2)