# Contributing to Initial-Pwn-Framework

Thank you for your interest in contributing to the Initial-Pwn-Framework!  
This project aims to centralize client-side initial access techniques for red teamers and penetration testers. Your contributions help expand its utility.

---

## Adding a New Technique

### 1. Fork the Repository
Create your own fork from the GitHub interface to begin making changes.

### 2. Create a Technique Folder
Navigate to either:
- `modules/windows/` — for Windows techniques
- `modules/linux/` — for Linux techniques

Create a folder using lowercase and hyphens.  
**Example:** `modules/windows/html-smuggling`

### 3. Create a README.md in That Folder
Use the module structure defined in `modules/template.md`.  
Your file must include:
- Overview
- How It Works
- Prerequisites
- Steps to implement
- Payload/Code Snippets
- Tips
- References
- Author : "author-name"

### 4. (Optional) Add a `/poc/` Directory
If your technique includes scripts, payloads, or additional files, place them in a subfolder named `poc/` inside the technique directory.

### 5. Update the Main `README.md`
Add your new technique to the list under the correct platform section, using a relative Markdown link.

Example:
```markdown
- [HTML Smuggling](modules/windows/html-smuggling/README.md)
```

### 6. Commit and Open a Pull Request

Push your changes and open a Pull Request. Please include:

- A clear and descriptive title
- A short summary of what your module does



## Tips for Quality Contributions

- Use neutral, professional language.
- Keep Markdown formatting clean and consistent.
- Test your code snippets when possible.
- Focus on real-world applicability for red teamers.



We appreciate your contributions, thank you for helping build a better offensive security resource!