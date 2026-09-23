<img width="400" height="400" alt="133052465" src="https://github.com/user-attachments/assets/24925f7c-53b1-459d-9310-7ad4cd0a5015" />



# system-prompt-dumper

Passive system prompt extraction via mitmproxy. Intercept, analyze, and verify API traffic from OpenAI, Google Gemini, Alibaba Qwen, and Anthropic — zero additional API cost, no trust required.

Stop trusting random dumps on Twitter. See exactly what system prompts, tool definitions, and instructions your AI clients are actually sending.

## Supported Providers

| Provider | Endpoint | Client Examples |
|----------|----------|-----------------|
| **OpenAI** | `api.openai.com` | openai-python, ChatGPT Desktop, various apps |
| **Google Gemini** | `generativelanguage.googleapis.com` | google-generativeai, AI Studio, Vertex AI |
| **Alibaba Qwen** | `dashscope.aliyuncs.com` | dashscope SDK, Qwen API clients |
| **Anthropic** | `api.anthropic.com` | Claude Code, claude-python, Claude Desktop |

## How It Works

1. Run mitmproxy in reverse mode pointing to the provider's API
2. Set the client's base URL to your local proxy
3. Every request is intercepted and the system prompt extracted
4. No modification to client code needed — completely passive

## Installation

```bash
# Install mitmproxy
pip install mitmproxy
# or
brew install mitmproxy

# Clone this repo
git clone https://github.com/YOUR_USERNAME/system-prompt-dumper.git
cd system-prompt-dumper
```

## Usage

### OpenAI

```bash
# Terminal 1: Start proxy
mitmweb --mode reverse:https://api.openai.com --listen-port 8000 -s extract_prompts.py

# Terminal 2: Run your OpenAI client through proxy
export OPENAI_BASE_URL=http://localhost:8000/v1
python your_openai_script.py
```

### Google Gemini

```bash
# Terminal 1
mitmweb --mode reverse:https://generativelanguage.googleapis.com --listen-port 8000 -s extract_prompts.py

# Terminal 2
export GOOGLE_API_BASE_URL=http://localhost:8000
python your_gemini_script.py
```

### Alibaba Qwen

```bash
# Terminal 1
mitmweb --mode reverse:https://dashscope.aliyuncs.com --listen-port 8000 -s extract_prompts.py

# Terminal 2
export DASHSCOPE_BASE_URL=http://localhost:8000
python your_qwen_script.py
```

### Anthropic Claude

```bash
# Terminal 1
mitmweb --mode reverse:https://api.anthropic.com --listen-port 8000 -s extract_prompts.py

# Terminal 2
export ANTHROPIC_BASE_URL=http://localhost:8000/
claude
```

## The Extractor

Save this as `extract_prompts.py`:

```python
import json
import os
import re
from datetime import datetime
from mitmproxy import http

class SystemPromptDumper:
    def __init__(self):
        self.output_dir = "extracted_prompts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.counter = 0
        
        # Provider detection patterns
        self.providers = {
            'openai': {
                'hosts': ['api.openai.com', 'openai.azure.com'],
                'system_keys': ['system', 'system_instruction'],
                'model_key': 'model',
            },
            'gemini': {
                'hosts': ['generativelanguage.googleapis.com', 'aiplatform.googleapis.com'],
                'system_keys': ['systemInstruction', 'system_instruction', 'system'],
                'model_key': 'model',
            },
            'qwen': {
                'hosts': ['dashscope.aliyuncs.com', 'dashscope.cn'],
                'system_keys': ['system', 'system_message', 'input.system'],
                'model_key': 'model',
            },
            'anthropic': {
                'hosts': ['api.anthropic.com'],
                'system_keys': ['system'],
                'model_key': 'model',
            }
        }

    def detect_provider(self, host: str) -> str:
        host = host.lower()
        for provider, config in self.providers.items():
            for h in config['hosts']:
                if h in host:
                    return provider
        return 'unknown'

    def extract_system_prompt(self, body: dict, provider: str) -> list:
        """Extract system prompt from request body based on provider format."""
        prompts = []
        config = self.providers.get(provider, {})
        system_keys = config.get('system_keys', ['system'])
        
        # Try each known key for the provider
        for key in system_keys:
            if '.' in key:
                # Handle nested keys like 'input.system'
                parts = key.split('.')
                current = body
                for part in parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        current = None
                        break
                if current:
                    prompts.append(self.normalize_prompt(current))
            elif key in body:
                prompts.append(self.normalize_prompt(body[key]))
        
        # Generic fallback: look for messages with system role
        if not prompts and 'messages' in body:
            for msg in body['messages']:
                if isinstance(msg, dict) and msg.get('role') == 'system':
                    prompts.append(self.normalize_prompt(msg.get('content', msg)))
        
        # Gemini specific: check contents array
        if not prompts and 'contents' in body and provider == 'gemini':
            for content in body['contents']:
                if isinstance(content, dict) and content.get('role') == 'system':
                    prompts.append(self.normalize_prompt(content.get('parts', content)))
        
        return prompts

    def normalize_prompt(self, prompt) -> str:
        """Normalize various prompt formats to string."""
        if isinstance(prompt, str):
            return prompt
        elif isinstance(prompt, list):
            # Handle array of text/content objects
            texts = []
            for item in prompt:
                if isinstance(item, dict):
                    if 'text' in item:
                        texts.append(item['text'])
                    elif 'content' in item:
                        texts.append(item['content'])
                elif isinstance(item, str):
                    texts.append(item)
            return '\n'.join(texts)
        elif isinstance(prompt, dict):
            if 'text' in prompt:
                return prompt['text']
            elif 'content' in prompt:
                return prompt['content']
            elif 'parts' in prompt:
                return self.normalize_prompt(prompt['parts'])
            else:
                return json.dumps(prompt, indent=2)
        return str(prompt)

    def request(self, flow: http.HTTPFlow) -> None:
        # Skip non-API traffic
        if not any(api in flow.request.pretty_host for api in 
                   ['openai', 'anthropic', 'googleapis', 'dashscope']):
            return
        
        # Only intercept POST/GET to generation endpoints
        if flow.request.method not in ['POST', 'GET']:
            return
            
        path = flow.request.path.lower()
        if not any(ep in path for ep in ['/v1/chat', '/v1/messages', '/v1/completions', 
                                          '/generatecontent', '/tokenize']):
            return

        try:
            body = json.loads(flow.request.content) if flow.request.content else {}
        except:
            return

        provider = self.detect_provider(flow.request.pretty_host)
        system_prompts = self.extract_system_prompt(body, provider)
        
        if not system_prompts:
            return

        self.counter += 1
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/{provider}_{timestamp}_{self.counter:04d}.txt"
        
        # Extract model info
        model = 'unknown'
        if provider in self.providers:
            model_key = self.providers[provider].get('model_key', 'model')
            model = body.get(model_key, body.get('model', 'unknown'))
        
        # Build output
        output = []
        output.append(f"{'='*70}")
        output.append(f"PROVIDER: {provider.upper()}")
        output.append(f"MODEL: {model}")
        output.append(f"ENDPOINT: {flow.request.method} {flow.request.path}")
        output.append(f"TIMESTAMP: {datetime.now().isoformat()}")
        output.append(f"{'='*70}")
        output.append("")
        
        for i, prompt in enumerate(system_prompts, 1):
            output.append(f"--- SYSTEM PROMPT PART {i}/{len(system_prompts)} ---")
            output.append(prompt)
            output.append("")
        
        output.append(f"{'='*70}")
        output.append("FULL REQUEST BODY (JSON):")
        output.append(f"{'='*70}")
        output.append(json.dumps(body, indent=2))
        
        content = '\n'.join(output)
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        
        # Console output (truncated)
        print(f"\n[+] {provider.upper()} system prompt captured -> {filename}")
        preview = system_prompts[0][:300] if system_prompts[0] else "empty"
        if len(system_prompts[0]) > 300:
            preview += "..."
        print(f"    Preview: {preview[:80]}...")
        print(f"    Model: {model}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Optional: capture responses for full conversation reconstruction."""
        pass

addons = [SystemPromptDumper()]
```

## Output Example

```
extracted_prompts/
├── anthropic_20240923_143022_0001.txt
├── openai_20240923_143045_0002.txt
└── gemini_20240923_143110_0003.txt
```

Each file contains:
- Provider and model info
- Full system prompt(s)
- Complete request body for verification

## Provider-Specific Notes

### OpenAI
- Works with `openai-python`, ChatGPT desktop app, and any OpenAI-compatible client
- Some clients use `api.openai.com`, others use Azure endpoints
- System prompt usually in `messages` array with `role: system`

### Google Gemini
- Uses `systemInstruction` field (camelCase)
- Also check `contents` array for system role
- Different API structure from OpenAI-compatible endpoints

### Alibaba Qwen
- Often uses `system` or `system_message` at top level
- Some endpoints nest under `input.system`
- DashScope SDK has specific header patterns

### Anthropic
- Clean `system` field at request root
- Claude Code sends massive prompts with tool definitions
- Watch for `CLAUDE.md` content injection

## Advanced: Full Traffic Capture

For complete request/response logging (including responses):

```python
# Add this to the SystemPromptDumper class

def response(self, flow: http.HTTPFlow) -> None:
    if not any(api in flow.request.pretty_host for api in 
               ['openai', 'anthropic', 'googleapis', 'dashscope']):
        return
    
    # Save response alongside request
    resp_file = f"{self.output_dir}/resp_{self.counter:04d}.json"
    with open(resp_file, "w") as f:
        json.dump({
            "status": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": json.loads(flow.response.content) if flow.response.content else None
        }, f, indent=2)
```

## Troubleshooting

**Certificate errors?**
Install the mitmproxy CA cert:
```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem

# Or visit http://mitm.it when proxy is running
```

**Client not connecting?**
- Verify `*_BASE_URL` environment variable is set correctly
- Check that mitmproxy is listening on the expected port
- Some clients need trailing slash, others don't

**Empty system prompts?**
- Some providers send system prompt as first message with `role: system`
- Check the full request body in the output file
- Provider may not use system prompts (rare)

## License

MIT. Do whatever. Verify don't trust.

---

*Stop retweeting system prompts, dump them yourself*
