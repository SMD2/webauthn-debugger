const script = document.createElement('script')
script.setAttribute("src", chrome.runtime.getURL('wrapper.js'));
(document.head || document.body || document.documentElement || document).appendChild(script)