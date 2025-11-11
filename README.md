# ShellCraft

**Multi-provider AI tool for organizing IDA disassembly into shellcode-ready blocks.**

Supports Claude, OpenAI, Gemini, and local models (Ollama) • x86/x64 auto-detection

---

### Why Not Just Use a C to shellcode generator like pe_to_shellcode or donut?
#### Different Goals, Different Tools:

###### Automated converters (pe_to_shellcode, donut, sRDI):
* Purpose: Convert complete executables to shellcode
* User: Red teamers who need working payloads fast
* Learning value: ❌ None - complete black box
* Control: ❌ Minimal - you get what you get
* Use case: Production operations

###### ShellCraft:
* Purpose: Organize compiler output for hand-crafted shellcode
* User: students, security researchers, learners
* Control: ✅ Complete - you decide what to keep, optimize, modify
* Learning value: ✅ High - you see and control every instruction
* Use case: Education, custom development, shellcode research

---

## Workflow

```
1. Write C code
   ↓
2. Compile (x86/x64)
   ↓
3. Disassemble in IDA
   ↓
4. Export to text
   ↓
5. shellcraft.py exported_asm.txt --dry-run  ← Safety check
   ↓
6. shellcraft.py exported_asm.txt -v         ← Process
   ↓
7. Use clean,commented,organized blocks to add to your shellcode
```

---

## Quick Start

```bash
# Install
pip install cryptography anthropic  # Claude (or openai, google-generativeai)

# Save token (one-time)
python shellcraft.py --save-token claude sk-ant-xxxxx

# Process file
python shellcraft.py revshell_asm.txt --dry-run  # Preview first
python shellcraft.py revshell_asm.txt -v         # Process
```

---

## AI Providers

Note! These prices are an approximation and might be **completely incorrect**, **look them up
with the AI provider for accurate pricing**.

### Supported

| Provider | Cost/File | Install | Token Required |
|----------|-----------|---------|----------------|
| **Claude** | ~$0.02 | `pip install anthropic` | Yes |
| **OpenAI** | ~$0.03 | `pip install openai` | Yes |
| **Gemini** | ~$0.01 | `pip install google-generativeai` | Yes |
| **Ollama** | FREE | `pip install requests` | No |

### List Available

```bash
python shellcraft.py --list-providers
```

#### Preprocessor
The pre-processor is built to remove any uneccery data to provide the model with
(hopefully) only relevant data and therefore a smaller input.

---


### Use Different Providers

```bash
# Claude (default)
python shellcraft.py file.txt

# OpenAI
python shellcraft.py file.txt --provider openai

# Gemini (cheapest)
python shellcraft.py file.txt --provider gemini

# Ollama (free, local)
python shellcraft.py file.txt --provider ollama --model qwen2.5-coder:7b -v
```

---

## Features

✅ **Multi-Provider AI** - Choose Claude, OpenAI, Gemini, or local models  
✅ **x86/x64 Support** - Auto-detects architecture  
✅ **Safety First** - Dry-run, preserve-all, validation warnings  
✅ **Smart Preprocessing** - Removes debug code automatically  
✅ **Complete Audit Trail** - Logs every removal  

---

## Key Commands

```bash
# Safety
shellcraft.py file.txt --dry-run           # Preview changes
shellcraft.py file.txt --preserve-all      # No removal
shellcraft.py file.txt --save-removed-log  # Track removals

# Architecture
shellcraft.py file.txt --arch x64          # Force x64

# Providers
shellcraft.py file.txt --provider openai   # Use ChatGPT
shellcraft.py file.txt --provider ollama   # Use local model

# Output
shellcraft.py file.txt -o custom.txt       # Custom output path
```

---

## Architecture Support

### x86 (32-bit)
- Stack-based parameters
- ESP/EBP frame pointers
- cdecl/stdcall conventions

### x64 (64-bit)
- Register parameters (rcx, rdx, r8, r9)
- Shadow space (32 bytes)
- 16-byte stack alignment
- Microsoft x64 calling convention

Auto-detected from register usage or force with `--arch`

---

## Output Format

```c
" wsa_startup:                       "
"   push    rcx                       ;" # First parameter (x64 fastcall)
"   mov     edx, 0x202                ;" # Second parameter (version 2.2)
"   call    qword ptr [WSAStartup]    ;" # Initialize Winsock

" create_socket:                     "
"   xor     r9d, r9d                  ;" # Fourth param (dwFlags = 0)
"   mov     r8d, 6                    ;" # Third param (IPPROTO_TCP)
"   ...
```

---

## Ollama Setup (Local & Free & Private)

##### Unix-like
```bash
# 1. Install Ollama (https://ollama.ai)
curl https://ollama.ai/install.sh | sh
```

##### Windows
```bash
# 1. Install Ollama (https://ollama.ai)
winget install Ollama.Ollama
```

##### 
```bash
# 2. Pull a model
ollama pull qwen2.5-coder:7b

# 3. Use with ShellCraft
python shellcraft.py file.txt --provider ollama --model qwen2.5-coder:7b -v
```

---

## Token Management

ShellCraft encrypts your API tokens using Fernet for convenience and basic obfuscation.
You don't have to re-type tokens, and they're safe from accidental exposure like
- git commits
- file sharing
- basic malware scanning for plaintext keys

**Good enough for:** Personal laptops, studying, development work  
**Not good enough for:** Shared machines, production secrets, compliance requirements

**The honest truth:** The encryption key lives on your machine (`~/.shellcraft/key.bin`), so this is "secure obfuscation" rather than true security. Anyone with access to your user account can decrypt the tokens - just like AWS CLI, Docker, and Git credentials work.

```bash
# Save tokens (encrypted storage)
python shellcraft.py --save-token claude sk-ant-xxxxx
python shellcraft.py --save-token openai sk-xxxxx
python shellcraft.py --save-token gemini xxxxx

# Tokens stored in ~/.shellcraft/<provider>_token.enc
```

---

## Troubleshooting

**"Provider not available"**  
→ Install: `pip install anthropic` (or openai, google-generativeai)

**"No token found"**  
→ Save: `python shellcraft.py --save-token <provider> <token>`

**"Too many lines removed"**  
→ Use: `python shellcraft.py file.txt --preserve-all`

**Ollama connection error**  
→ Start Ollama: `ollama serve`

---

## Files

- `shellcraft.py` - Main tool
- `requirements.txt` - Dependencies
- `~/.shellcraft/` - Token storage
