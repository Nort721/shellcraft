#!/usr/bin/env python3
"""
ShellCraft - IDA Assembly Reorganizer for Shellcode Development
"""

import argparse
import os
import re
import sys
import json
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
from cryptography.fernet import Fernet

# Import AI providers (gracefully handle missing ones)
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    import requests
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


# Configuration
CONFIG_DIR = Path.home() / ".shellcraft"
KEY_FILE = CONFIG_DIR / "key.bin"


@dataclass
class ProviderConfig:
    """Configuration for an AI provider."""
    name: str
    available: bool
    requires_token: bool
    default_model: str
    cost_per_1k_tokens: float
    context_window: int


# Provider configurations
PROVIDERS = {
    'claude': ProviderConfig(
        name='Claude (Anthropic)',
        available=ANTHROPIC_AVAILABLE,
        requires_token=True,
        default_model='claude-sonnet-4-20250514',
        cost_per_1k_tokens=0.003,
        context_window=200000
    ),
    'openai': ProviderConfig(
        name='OpenAI (ChatGPT)',
        available=OPENAI_AVAILABLE,
        requires_token=True,
        default_model='gpt-4o',
        cost_per_1k_tokens=0.0025,
        context_window=128000
    ),
    'gemini': ProviderConfig(
        name='Google Gemini',
        available=GEMINI_AVAILABLE,
        requires_token=True,
        default_model='gemini-1.5-pro',
        cost_per_1k_tokens=0.00125,
        context_window=1000000
    ),
    'ollama': ProviderConfig(
        name='Ollama (Local)',
        available=OLLAMA_AVAILABLE,
        requires_token=False,
        default_model='codellama:13b',
        cost_per_1k_tokens=0.0,
        context_window=32000
    ),
}


@dataclass
class AssemblyLine:
    """Represents a parsed assembly instruction line."""
    address: str
    instruction: str
    operands: str
    comment: str
    original: str
    is_label: bool = False
    is_function_start: bool = False


class TokenManager:
    """Securely manages API tokens with encryption."""
    
    def __init__(self):
        """Initialize token manager and ensure config directory exists."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    def _get_or_create_key(self) -> bytes:
        """Get existing encryption key or create a new one."""
        if KEY_FILE.exists():
            return KEY_FILE.read_bytes()
        else:
            key = Fernet.generate_key()
            KEY_FILE.write_bytes(key)
            os.chmod(KEY_FILE, 0o600)
            return key
    
    def save_token(self, provider: str, token: str) -> None:
        """
        Encrypt and save API token to disk.
        
        Args:
            provider: Provider name (claude, openai, gemini)
            token: The API token to save
        """
        token_file = CONFIG_DIR / f"{provider}_token.enc"
        key = self._get_or_create_key()
        fernet = Fernet(key)
        encrypted_token = fernet.encrypt(token.encode())
        token_file.write_bytes(encrypted_token)
        os.chmod(token_file, 0o600)
        print(f"✓ {provider.title()} token saved securely to {token_file}")
    
    def load_token(self, provider: str) -> Optional[str]:
        """
        Load and decrypt API token from disk.
        
        Args:
            provider: Provider name
            
        Returns:
            The decrypted API token, or None if not found
        """
        token_file = CONFIG_DIR / f"{provider}_token.enc"
        if not token_file.exists():
            return None
        
        key = self._get_or_create_key()
        fernet = Fernet(key)
        encrypted_token = token_file.read_bytes()
        return fernet.decrypt(encrypted_token).decode()


class AssemblyPreprocessor:
    """Preprocesses IDA disassembly output before AI processing."""
    
    # Patterns for debug/runtime checks to remove (CONSERVATIVE)
    DEBUG_PATTERNS = [
        r'__\$EncStackInit.*',
        r'.*__CheckForDebuggerJustMyCode.*',
        r'.*__RTC_CheckEsp.*',
        r'.*__RTC_CheckStackVars.*',
        r'.*_RTC_.*',
        r'.*JMC_flag.*',
    ]
    
    # Architecture-specific registers
    X86_REGISTERS = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'}
    X64_REGISTERS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                     'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}
    
    def __init__(self, verbose: bool = False, preserve_all: bool = False, arch: Optional[str] = None):
        self.verbose = verbose
        self.preserve_all = preserve_all
        self.forced_arch = arch
        self.detected_arch = None
        self.stats = {
            'total_lines': 0,
            'code_lines': 0,
            'debug_lines_removed': 0,
            'empty_lines_removed': 0,
            'comments_extracted': 0,
            'removed_lines': [],
        }
    
    def detect_architecture(self, lines: List[AssemblyLine]) -> str:
        """Detect architecture (x86 or x64) from register usage."""
        if self.forced_arch:
            return self.forced_arch
        
        x86_count = sum(1 for line in lines[:100] 
                       if any(reg in line.operands.lower() for reg in self.X86_REGISTERS))
        x64_count = sum(1 for line in lines[:100] 
                       if any(reg in line.operands.lower() for reg in self.X64_REGISTERS))
        
        self.detected_arch = 'x64' if x64_count > x86_count else 'x86'
        
        if self.verbose:
            print(f"→ Detected architecture: {self.detected_arch}")
        
        return self.detected_arch
    
    def parse_ida_line(self, line: str) -> Optional[AssemblyLine]:
        """Parse a single line of IDA disassembly."""
        self.stats['total_lines'] += 1
        line = line.strip()
        
        if not line:
            self.stats['empty_lines_removed'] += 1
            return None
        
        # Check for debug patterns
        if not self.preserve_all:
            for pattern in self.DEBUG_PATTERNS:
                if re.match(pattern, line):
                    self.stats['debug_lines_removed'] += 1
                    self.stats['removed_lines'].append({
                        'line': line,
                        'reason': f'Debug pattern: {pattern[:30]}...'
                    })
                    return None
        
        # Extract comment
        comment = ""
        if ';' in line:
            parts = line.split(';', 1)
            line = parts[0].strip()
            comment = parts[1].strip()
            if comment:
                self.stats['comments_extracted'] += 1
        
        # Parse .text:ADDRESS format
        address_match = re.match(r'\.text:([0-9A-Fa-f]+)\s+(.*)', line)
        if not address_match:
            return None
        
        address = address_match.group(1)
        rest = address_match.group(2).strip()
        
        # Check if label or function start
        is_label = rest.endswith(':')
        is_function_start = 'proc near' in rest or 'proc far' in rest
        
        if is_label or is_function_start:
            return AssemblyLine(
                address=address, instruction=rest, operands="",
                comment=comment, original=line, is_label=True,
                is_function_start=is_function_start
            )
        
        # Parse instruction and operands
        parts = rest.split(None, 1)
        instruction = parts[0] if parts else ""
        operands = parts[1] if len(parts) > 1 else ""
        
        self.stats['code_lines'] += 1
        
        return AssemblyLine(
            address=address, instruction=instruction, operands=operands,
            comment=comment, original=line
        )
    
    def remove_stack_checks(self, lines: List[AssemblyLine]) -> List[AssemblyLine]:
        """Remove debug stack checking code (architecture-aware)."""
        if self.preserve_all:
            return lines
        
        filtered = []
        skip_next = False
        arch = self.detected_arch or 'x86'
        stack_ptr = 'rsp' if arch == 'x64' else 'esp'
        temp_reg = 'rsi' if arch == 'x64' else 'esi'
        
        for i, line in enumerate(lines):
            if skip_next:
                skip_next = False
                continue
            
            # Pattern: mov temp_reg, stack_ptr followed by comparison
            if (line.instruction == 'mov' and 
                temp_reg in line.operands.lower() and 
                stack_ptr in line.operands.lower()):
                
                if i + 1 < len(lines) and 'cmp' in lines[i + 1].instruction.lower():
                    self.stats['removed_lines'].append({
                        'line': line.original,
                        'reason': f'Stack check ({arch})'
                    })
                    skip_next = True
                    if i + 2 < len(lines) and 'call' in lines[i + 2].instruction.lower():
                        if 'CheckEsp' in lines[i + 2].operands or 'CheckStackVars' in lines[i + 2].operands:
                            self.stats['removed_lines'].append({
                                'line': lines[i + 2].original,
                                'reason': f'Stack check call ({arch})'
                            })
                            lines[i + 2] = None
                    continue
            
            # Skip isolated comparisons
            if (line.instruction == 'cmp' and 
                temp_reg in line.operands.lower() and 
                stack_ptr in line.operands.lower()):
                self.stats['removed_lines'].append({
                    'line': line.original,
                    'reason': f'Stack check comparison ({arch})'
                })
                continue
            
            if line:
                filtered.append(line)
        
        return [l for l in filtered if l is not None]
    
    def identify_function_boundaries(self, lines: List[AssemblyLine]) -> List[Tuple[int, int, str]]:
        """Identify function boundaries."""
        functions = []
        current_function = None
        current_start = None
        
        for idx, line in enumerate(lines):
            if line.is_function_start:
                if current_function and current_start is not None:
                    functions.append((current_start, idx - 1, current_function))
                func_name = line.instruction.split()[0].replace('_', '')
                current_function = func_name
                current_start = idx
            elif 'endp' in line.instruction.lower():
                if current_function and current_start is not None:
                    functions.append((current_start, idx, current_function))
                    current_function = None
                    current_start = None
        
        return functions
    
    def group_api_calls(self, lines: List[AssemblyLine]) -> List[Tuple[int, str]]:
        """Identify Windows API calls."""
        api_calls = []
        # Pattern looks for __imp__ in the full line (instruction + operands)
        api_pattern = re.compile(r'(__imp__|ds:__imp__|cs:__imp__)_?([A-Za-z0-9_]+)')
        
        for idx, line in enumerate(lines):
            # Check both operands and full original line for API calls
            full_line = f"{line.instruction} {line.operands}"
            match = api_pattern.search(full_line)
            if match:
                api_name = match.group(2).replace('@', '').replace('_', '', 1)  # Remove leading underscore and @
                api_calls.append((idx, api_name))
        
        return api_calls
    
    def format_for_ai(self, lines: List[AssemblyLine]) -> str:
        """Format preprocessed assembly for AI consumption."""
        output = []
        for line in lines:
            if line.is_label:
                output.append(f"\n{line.instruction}")
            else:
                parts = [line.instruction]
                if line.operands:
                    parts.append(line.operands)
                asm_line = f"   {' '.join(parts):40s}"
                if line.comment:
                    asm_line += f"; {line.comment}"
                output.append(asm_line)
        return '\n'.join(output)
    
    def process(self, input_text: str) -> Tuple[str, dict]:
        """Main preprocessing pipeline."""
        lines = input_text.split('\n')
        
        if self.verbose:
            print(f"→ Parsing {len(lines)} lines...")
        
        # Parse all lines
        parsed_lines = [self.parse_ida_line(line) for line in lines]
        parsed_lines = [l for l in parsed_lines if l]
        
        if self.verbose:
            print(f"→ Identified {len(parsed_lines)} code lines")
        
        # Detect architecture
        architecture = self.detect_architecture(parsed_lines)
        
        # Remove stack checks
        if not self.preserve_all:
            parsed_lines = self.remove_stack_checks(parsed_lines)
        
        if self.verbose:
            print(f"→ After cleanup: {len(parsed_lines)} lines")
        
        # Identify functions and API calls
        functions = self.identify_function_boundaries(parsed_lines)
        api_calls = self.group_api_calls(parsed_lines)
        
        self.stats['functions_found'] = len(functions)
        self.stats['api_calls_found'] = len(api_calls)
        
        if self.verbose:
            print(f"→ Found {len(functions)} functions, {len(api_calls)} API calls")
        
        # Format for AI
        formatted = self.format_for_ai(parsed_lines)
        
        # Add metadata
        metadata = {
            'architecture': architecture,
            'functions': [name for _, _, name in functions],
            'api_calls': [name for _, name in api_calls],
            'line_count': len(parsed_lines)
        }
        
        self.stats['metadata'] = metadata
        self.stats['architecture'] = architecture
        
        return formatted, self.stats


class AIOrganizer(ABC):
    """Abstract base class for AI providers."""
    
    SYSTEM_PROMPT = """You are an expert in x86/x64 assembly and shellcode development.

Organize IDA disassembly into clean, labeled blocks for shellcode development.

Format as Python strings:
" block_name:                        "
"   instruction  operands             ;" # clear comment

Requirements:
1. Descriptive snake_case block names
2. Clear comments on each instruction's purpose
3. Architecture-aware (x86 vs x64 calling conventions)
4. Mark API calls and critical operations
5. Add optimization notes at the end

Output should be ready for shellcode development."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    @abstractmethod
    def organize(self, preprocessed_code: str, stats: dict) -> str:
        """Organize assembly code into blocks."""
        pass
    
    def _build_prompt(self, preprocessed_code: str, stats: dict) -> str:
        """Build user prompt with metadata."""
        metadata = stats['metadata']
        return f"""Organize this IDA {metadata['architecture']} disassembly into shellcode blocks.

Metadata:
- Architecture: {metadata['architecture']}
- Functions: {', '.join(metadata['functions']) or 'None'}
- API Calls: {', '.join(metadata['api_calls']) or 'None'}
- Lines: {metadata['line_count']}

Assembly Code:
{preprocessed_code}

Provide organized blocks with clear comments and {metadata['architecture']}-specific optimization notes."""


class ClaudeOrganizer(AIOrganizer):
    """Claude (Anthropic) provider."""
    
    def __init__(self, api_key: str, model: str = None, verbose: bool = False):
        super().__init__(verbose)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model or PROVIDERS['claude'].default_model
    
    def organize(self, preprocessed_code: str, stats: dict) -> str:
        if self.verbose:
            print(f"→ Using Claude ({self.model})...")
        
        message = self.client.messages.create(
            model=self.model,
            max_tokens=16000,
            temperature=0.3,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": self._build_prompt(preprocessed_code, stats)}]
        )
        
        if self.verbose:
            print(f"→ Tokens: {message.usage.input_tokens} in, {message.usage.output_tokens} out")
        
        return message.content[0].text


class OpenAIOrganizer(AIOrganizer):
    """OpenAI (ChatGPT) provider."""
    
    def __init__(self, api_key: str, model: str = None, verbose: bool = False):
        super().__init__(verbose)
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model or PROVIDERS['openai'].default_model
    
    def organize(self, preprocessed_code: str, stats: dict) -> str:
        if self.verbose:
            print(f"→ Using OpenAI ({self.model})...")
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": self._build_prompt(preprocessed_code, stats)}
            ],
            temperature=0.3,
            max_tokens=16000
        )
        
        if self.verbose:
            print(f"→ Tokens: {response.usage.prompt_tokens} in, {response.usage.completion_tokens} out")
        
        return response.choices[0].message.content


class GeminiOrganizer(AIOrganizer):
    """Google Gemini provider."""
    
    def __init__(self, api_key: str, model: str = None, verbose: bool = False):
        super().__init__(verbose)
        genai.configure(api_key=api_key)
        self.model_name = model or PROVIDERS['gemini'].default_model
        self.model = genai.GenerativeModel(self.model_name)
    
    def organize(self, preprocessed_code: str, stats: dict) -> str:
        if self.verbose:
            print(f"→ Using Gemini ({self.model_name})...")
        
        full_prompt = f"{self.SYSTEM_PROMPT}\n\n{self._build_prompt(preprocessed_code, stats)}"
        response = self.model.generate_content(
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=16000
            )
        )
        
        return response.text


class OllamaOrganizer(AIOrganizer):
    """Ollama (Local) provider."""
    
    def __init__(self, model: str = None, host: str = "http://localhost:11434", verbose: bool = False):
        super().__init__(verbose)
        self.model = model or PROVIDERS['ollama'].default_model
        self.host = host
    
    def organize(self, preprocessed_code: str, stats: dict) -> str:
        if self.verbose:
            print(f"→ Using Ollama ({self.model})...")
        
        response = requests.post(
            f"{self.host}/api/generate",
            json={
                "model": self.model,
                "prompt": f"{self.SYSTEM_PROMPT}\n\n{self._build_prompt(preprocessed_code, stats)}",
                "stream": False,
                "options": {"temperature": 0.3}
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Ollama error: {response.text}")
        
        return response.json()['response']


class ProviderFactory:
    """Factory for creating AI providers."""
    
    @staticmethod
    def create(provider: str, api_key: Optional[str] = None, model: Optional[str] = None, 
               verbose: bool = False) -> AIOrganizer:
        """Create an AI provider instance."""
        if provider == 'claude':
            if not ANTHROPIC_AVAILABLE:
                raise ImportError("Anthropic not installed. Run: pip install anthropic")
            if not api_key:
                raise ValueError("Claude requires an API key")
            return ClaudeOrganizer(api_key, model, verbose)
        
        elif provider == 'openai':
            if not OPENAI_AVAILABLE:
                raise ImportError("OpenAI not installed. Run: pip install openai")
            if not api_key:
                raise ValueError("OpenAI requires an API key")
            return OpenAIOrganizer(api_key, model, verbose)
        
        elif provider == 'gemini':
            if not GEMINI_AVAILABLE:
                raise ImportError("Google Generative AI not installed. Run: pip install google-generativeai")
            if not api_key:
                raise ValueError("Gemini requires an API key")
            return GeminiOrganizer(api_key, model, verbose)
        
        elif provider == 'ollama':
            if not OLLAMA_AVAILABLE:
                raise ImportError("Requests not installed. Run: pip install requests")
            return OllamaOrganizer(model, verbose=verbose)
        
        else:
            raise ValueError(f"Unknown provider: {provider}")
    
    @staticmethod
    def list_available() -> Dict[str, ProviderConfig]:
        """List available providers."""
        return {k: v for k, v in PROVIDERS.items() if v.available}


def validate_preprocessing(original_lines: int, processed_lines: int, 
                          removed_lines: list, api_calls: list) -> bool:
    """Validate preprocessing didn't remove critical code."""
    warnings = []
    
    # Check removal percentage
    if removed_lines and original_lines > 0:
        removal_pct = (len(removed_lines) / original_lines) * 100
        if removal_pct > 40:
            warnings.append(f"⚠ WARNING: {removal_pct:.1f}% of lines removed")
    
    # Check for suspicious patterns in removed lines
    suspicious = [r'call\s+.*[^_](WSA|CreateProcess|LoadLibrary)', r'push\s+offset.*', r'lea\s+.*']
    for item in removed_lines:
        for pattern in suspicious:
            if re.search(pattern, item['line'], re.IGNORECASE):
                warnings.append(f"⚠ WARNING: Suspicious removal: {item['line'][:60]}")
    
    # Check API calls exist
    if not api_calls and original_lines > 50:
        warnings.append("⚠ WARNING: No API calls detected")
    
    if warnings:
        print("\n" + "!" * 60)
        print("VALIDATION WARNINGS")
        print("!" * 60)
        for w in warnings:
            print(w)
        print("!" * 60 + "\n")
        return False
    
    return True


def save_removed_lines_log(output_path: Path, removed_lines: list) -> Path:
    """Save log of removed lines."""
    if not removed_lines:
        return None
    
    log_path = output_path.parent / f"{output_path.stem}_removed.log"
    
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("REMOVED LINES LOG - VERIFY THESE ARE DEBUG CODE ONLY\n")
        f.write("=" * 80 + "\n\n")
        
        for i, item in enumerate(removed_lines, 1):
            f.write(f"\n[{i}] Reason: {item['reason']}\n")
            f.write(f"    Line: {item['line']}\n")
        
        f.write(f"\n{'=' * 80}\nTotal: {len(removed_lines)} lines\n{'=' * 80}\n")
    
    return log_path


def print_statistics(stats: dict) -> None:
    """Print preprocessing statistics."""
    print("\n" + "=" * 60)
    print("STATISTICS")
    print("=" * 60)
    print(f"Architecture:     {stats.get('architecture', 'Unknown')}")
    print(f"Lines processed:  {stats['code_lines']}")
    print(f"Lines removed:    {len(stats.get('removed_lines', []))}")
    print(f"Functions found:  {stats.get('functions_found', 0)}")
    print(f"API calls found:  {stats.get('api_calls_found', 0)}")
    print("=" * 60 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ShellCraft - IDA Assembly Reorganizer with Multi-Provider AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Save tokens
  %(prog)s --save-token claude sk-ant-xxxxx
  %(prog)s --save-token openai sk-xxxxx
  
  # Process with Claude (default)
  %(prog)s file.txt
  
  # Use OpenAI
  %(prog)s file.txt --provider openai
  
  # Use local model (free!)
  %(prog)s file.txt --provider ollama
  
  # Safety checks
  %(prog)s file.txt --dry-run
  %(prog)s file.txt --preserve-all
  
  # List available providers
  %(prog)s --list-providers
        """
    )
    
    parser.add_argument('input_file', nargs='?', type=Path, help='Input IDA assembly file')
    parser.add_argument('--save-token', nargs=2, metavar=('PROVIDER', 'TOKEN'), 
                       help='Save API token for provider')
    parser.add_argument('--provider', choices=['claude', 'openai', 'gemini', 'ollama'],
                       default='claude', help='AI provider to use')
    parser.add_argument('--model', help='Specific model to use')
    parser.add_argument('--list-providers', action='store_true', help='List available providers')
    parser.add_argument('-o', '--output', type=Path, help='Output file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--arch', choices=['x86', 'x64'], help='Force architecture')
    parser.add_argument('--preserve-all', action='store_true', help='Preserve all lines')
    parser.add_argument('--save-removed-log', action='store_true', help='Save removed lines log')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be removed')
    
    args = parser.parse_args()
    
    token_manager = TokenManager()
    
    # Handle --list-providers
    if args.list_providers:
        print("\n" + "=" * 60)
        print("AVAILABLE AI PROVIDERS")
        print("=" * 60)
        for name, config in PROVIDERS.items():
            status = "✓ Available" if config.available else "✗ Not installed"
            token_req = "Requires token" if config.requires_token else "No token needed"
            cost = f"${config.cost_per_1k_tokens:.4f}/1K tokens" if config.cost_per_1k_tokens > 0 else "FREE"
            print(f"\n{name}:")
            print(f"  Name:    {config.name}")
            print(f"  Status:  {status}")
            print(f"  Auth:    {token_req}")
            print(f"  Model:   {config.default_model}")
            print(f"  Cost:    {cost}")
            print(f"  Context: {config.context_window:,} tokens")
        print("\n" + "=" * 60)
        return 0
    
    # Handle --save-token
    if args.save_token:
        provider, token = args.save_token
        if provider not in PROVIDERS:
            print(f"✗ Unknown provider: {provider}")
            print(f"  Available: {', '.join(PROVIDERS.keys())}")
            return 1
        token_manager.save_token(provider, token)
        return 0
    
    # Validate input file
    if not args.input_file:
        parser.print_help()
        return 1
    
    if not args.input_file.exists():
        print(f"✗ Error: File not found: {args.input_file}")
        return 1
    
    # Get API key if needed
    provider_config = PROVIDERS[args.provider]
    api_key = None
    
    if provider_config.requires_token:
        api_key = token_manager.load_token(args.provider)
        if not api_key:
            print(f"✗ Error: No {args.provider} token found")
            print(f"  Run: {sys.argv[0]} --save-token {args.provider} <your-token>")
            return 1
    
    # Check provider availability
    if not provider_config.available:
        print(f"✗ Error: {provider_config.name} not available")
        print(f"  Install with: pip install {args.provider}")
        return 1
    
    # Determine output path
    output_path = args.output or args.input_file.parent / f"{args.input_file.stem}_organized.txt"
    
    if args.verbose:
        print(f"Input:    {args.input_file}")
        print(f"Output:   {output_path}")
        print(f"Provider: {provider_config.name}")
        print()
    
    # Read input
    try:
        input_text = args.input_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        input_text = args.input_file.read_text(encoding='latin-1')
    
    # Preprocess
    print("→ Preprocessing assembly...")
    preprocessor = AssemblyPreprocessor(
        verbose=args.verbose,
        preserve_all=args.preserve_all,
        arch=args.arch
    )
    
    # Handle dry-run
    if args.dry_run:
        print("\n⚠ DRY RUN MODE")
        _, test_stats = preprocessor.process(input_text)
        print_statistics(test_stats)
        if test_stats.get('removed_lines'):
            print("First 10 removals:")
            for i, item in enumerate(test_stats['removed_lines'][:10], 1):
                print(f"  [{i}] {item['reason']}: {item['line'][:60]}")
        return 0
    
    preprocessed_code, stats = preprocessor.process(input_text)
    
    if args.stats or args.verbose:
        print_statistics(stats)
    
    # Validate
    if not args.preserve_all:
        validate_preprocessing(
            stats['code_lines'],
            stats['metadata']['line_count'],
            stats.get('removed_lines', []),
            stats['metadata']['api_calls']
        )
    
    # Save removed log
    if args.save_removed_log or args.verbose:
        if stats.get('removed_lines'):
            log_path = save_removed_lines_log(output_path, stats['removed_lines'])
            if log_path:
                print(f"→ Removed lines log: {log_path}")
    
    # Organize with AI
    print(f"→ Organizing with {provider_config.name}...")
    try:
        organizer = ProviderFactory.create(
            args.provider,
            api_key,
            args.model,
            args.verbose
        )
        organized_code = organizer.organize(preprocessed_code, stats)
    except Exception as e:
        print(f"✗ Error: {e}")
        return 1
    
    # Write output
    output_path.write_text(organized_code, encoding='utf-8')
    
    print(f"\n✓ Success! Output: {output_path}")
    print(f"  Architecture: {stats.get('architecture')}")
    print(f"  Provider: {provider_config.name}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())