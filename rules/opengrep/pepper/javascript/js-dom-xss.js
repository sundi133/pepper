const name = new URLSearchParams(location.search).get('name');
// ruleid: pepper.js.dom-xss
document.getElementById('greeting').innerHTML = 'Hello ' + name;
// ruleid: pepper.js.dom-xss
document.write(location.hash.substring(1));
// ok: pepper.js.dom-xss
document.getElementById('greeting').textContent = 'Hello ' + name;
// ok: pepper.js.dom-xss
document.getElementById('greeting').innerHTML = DOMPurify.sanitize(name);
// ok: pepper.js.dom-xss
document.getElementById('static').innerHTML = '<b>Welcome</b>';
