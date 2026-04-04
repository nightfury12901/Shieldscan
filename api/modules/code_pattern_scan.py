"""
Dangerous code pattern scanner.
Uses regex + simple AST-like matching to detect insecure coding patterns.
"""
import re
from typing import Any
import ast

# ─────────────────────────────────────────────
# Pattern definitions
# (name, pattern, severity, category, description, fix_steps)
# ─────────────────────────────────────────────
CODE_PATTERNS = [
    (
        "eval() with variable input",
        re.compile(r"\beval\s*\(\s*(?!\s*['\"`])", re.MULTILINE),
        "critical", "dangerous_code",
        "Your code uses eval() with a dynamic value. If that value comes from user input, an attacker can execute any code they want on your server.",
        "1. Remove eval() from your code\n2. Find a safer alternative — eval() is almost never necessary\n3. If evaluating math expressions, use a dedicated math library",
    ),
    (
        "exec() with variable input",
        re.compile(r"\bexec\s*\(\s*(?!\s*['\"`])", re.MULTILINE),
        "critical", "dangerous_code",
        "exec() with dynamic input allows attackers to run arbitrary code on your server.",
        "1. Never pass user input to exec()\n2. Use subprocess with explicit arguments list instead of shell strings",
    ),
    (
        "Shell injection: subprocess shell=True",
        re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", re.MULTILINE),
        "critical", "shell_injection",
        "Your code runs shell commands with shell=True. If any part of the command comes from user input, an attacker can inject shell commands and take over your server.",
        "1. Use shell=False (the default)\n2. Pass command as a list: subprocess.run(['ls', '-la']) instead of a string\n3. Never include user input in shell commands",
    ),
    (
        "os.system() call",
        re.compile(r"\bos\.system\s*\(", re.MULTILINE),
        "critical", "shell_injection",
        "os.system() passes a string directly to the shell. If any user input is included, it creates a shell injection vulnerability.",
        "1. Replace os.system() with subprocess.run() using a list of arguments\n2. Never concatenate user input into system commands",
    ),
    (
        "SQL string concatenation",
        re.compile(r"(?i)(execute|query|cursor\.execute)\s*\(\s*[f\"].*?(WHERE|SELECT|INSERT|UPDATE|DELETE).*?\+", re.MULTILINE),
        "critical", "sqli_code",
        "Your code builds SQL queries by joining strings together. If any variable contains user input, attackers can manipulate the query to read, modify, or delete your entire database (SQL Injection).",
        "1. Use parameterized queries (prepared statements)\n2. Example fix: cursor.execute('SELECT * FROM users WHERE id=%s', [user_id])\n3. NEVER build SQL by concatenating strings with user input",
    ),
    (
        "pickle.loads() deserialization",
        re.compile(r"\bpickle\.loads?\s*\(", re.MULTILINE),
        "critical", "dangerous_deserialization",
        "Your code deserializes data using pickle. Pickle is fundamentally insecure — deserializing untrusted data allows an attacker to execute any code on your server.",
        "1. Never deserialize untrusted data with pickle\n2. Use JSON or a schema-validated format instead\n3. If pickle is required for internal data, ensure it never touches untrusted user input",
    ),
    (
        "yaml.load() without Loader",
        re.compile(r"\byaml\.load\s*\([^,)]+\)", re.MULTILINE),
        "critical", "dangerous_deserialization",
        "yaml.load() without a Loader argument can execute arbitrary Python code when parsing untrusted YAML input.",
        "1. Always use yaml.safe_load() instead of yaml.load()\n2. If you need full YAML, use yaml.load(data, Loader=yaml.SafeLoader)",
    ),
    (
        "MD5 used for passwords",
        re.compile(r"(?i)hashlib\.md5\s*\(|md5\(.*password", re.MULTILINE),
        "critical", "weak_crypto",
        "Your code uses MD5 to hash passwords. MD5 is broken — attackers can reverse MD5 hashes in seconds using rainbow tables. Your users' passwords are effectively stored in plain text.",
        "1. Use bcrypt, scrypt, or Argon2 for password hashing — NEVER MD5 or SHA1\n2. Python: use bcrypt.hashpw() or passlib\n3. Migrate existing MD5 hashes: on next user login, re-hash with the new algorithm",
    ),
    (
        "SHA1 used for passwords",
        re.compile(r"(?i)hashlib\.sha1\s*\(|sha1\(.*password", re.MULTILINE),
        "critical", "weak_crypto",
        "SHA1 is broken for password hashing. Attackers can crack SHA1 password hashes very quickly.",
        "1. Replace SHA1 with bcrypt, scrypt, or Argon2\n2. SHA1 is acceptable for checksums but never for passwords",
    ),
    (
        "Math.random() for security tokens",
        re.compile(r"Math\.random\(\)", re.MULTILINE),
        "medium", "weak_crypto",
        "Math.random() is not cryptographically secure. Using it for tokens, session IDs, or passwords means an attacker may be able to predict the values.",
        "1. Use crypto.randomBytes() in Node.js\n2. Or in browsers: crypto.getRandomValues()\n3. Never use Math.random() for anything security-related",
    ),
    (
        "Insecure CORS: Allow-Origin *",
        re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*", re.MULTILINE),
        "medium", "insecure_cors",
        "Your application allows requests from any website (CORS *). Malicious websites can make API requests to your server while impersonating your logged-in users.",
        "1. Replace * with your specific frontend domain\n2. Example: Access-Control-Allow-Origin: https://yourapp.com\n3. If multiple origins are needed, whitelist them explicitly in your server code",
    ),
    (
        "Debug mode enabled (Python)",
        re.compile(r"(?i)(DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)", re.MULTILINE),
        "medium", "debug_mode",
        "Your application has debug mode turned on. In production, debug mode exposes detailed error messages, stack traces, and sometimes an interactive debugger — all visible to attackers.",
        "1. Set DEBUG = False in your production configuration\n2. Use environment variables: DEBUG = os.getenv('DEBUG', 'False') == 'True'\n3. Never deploy to production with debug=True",
    ),
    (
        "Debug mode enabled (Node/Express)",
        re.compile(r"(?i)NODE_ENV\s*=\s*['\"]?development['\"]?|app\.set\s*\(\s*['\"]env['\"],\s*['\"]development['\"]\s*\)", re.MULTILINE),
        "low", "debug_mode",
        "The application appears to be configured for development mode, which may expose verbose error messages in production.",
        "1. Set NODE_ENV=production in your production environment\n2. Never hardcode NODE_ENV=development in deployed code",
    ),
    (
        "JWT 'none' algorithm",
        re.compile(r'(?i)algorithm\s*[=:]\s*[\'"]none[\'"]|alg\s*[=:]\s*[\'"]none[\'"]', re.MULTILINE),
        "critical", "jwt_none_alg",
        "Your code uses the 'none' algorithm for JWT tokens. This means tokens have no signature — anyone can craft a valid token for any user, completely bypassing authentication.",
        "1. Always use a real algorithm: RS256 (recommended) or HS256\n2. Verify that your JWT library rejects 'none' algorithm by default\n3. Never allow the algorithm to be specified in the token payload",
    ),
    (
        "Hardcoded Private IP Address",
        re.compile(
            r"""['"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})['"]""",
            re.MULTILINE,
        ),
        "medium", "information_disclosure",
        "A private/internal IP address is hardcoded in your source code. This exposes your internal network topology to anyone who reads the code, including attackers accessing your repository.",
        "1. Move all internal IPs to environment variables\n2. Use service discovery or DNS names instead of hardcoded IPs\n3. Add .env to .gitignore and use .env.example with placeholder values",
    ),
    (
        "Docker: Privileged Container",
        re.compile(r"--privileged", re.MULTILINE),
        "critical", "container_security",
        "A --privileged Docker container is defined. This gives the container full access to the host system. A compromised privileged container lets attackers escape and gain root on the server.",
        "1. Remove --privileged from all container definitions\n2. Grant only specific capabilities using --cap-add\n3. Use rootless containers for additional isolation",
    ),
    (
        "Docker: Secret in ENV instruction",
        re.compile(r"(?i)^\s*ENV\s+(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET|DATABASE_URL)\s*=\s*\S+", re.MULTILINE),
        "critical", "container_security",
        "A Dockerfile sets a secret value in an ENV instruction. Docker image layers are permanent — secrets are baked into the image and visible via 'docker history' to anyone with image access.",
        "1. Never set secrets in Dockerfile ENV instructions\n2. Pass secrets at runtime: docker run -e SECRET=value\n3. Use Docker secrets, Vault, or AWS Secrets Manager in production",
    ),
]


async def scan_code_patterns(files: list[dict]) -> list[dict]:
    findings = []
    seen_signatures = set()

    SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__", ".next"}
    SKIP_EXTS = {".min.js", ".map", ".png", ".jpg", ".gif", ".svg", ".pdf", ".zip"}

    for file_obj in files:
        path = file_obj.get("path", "")
        content = file_obj.get("content", "")

        if any(f"/{skip}/" in f"/{path}" or path.startswith(f"{skip}/") for skip in SKIP_DIRS):
            continue
        if any(path.endswith(ext) for ext in SKIP_EXTS):
            continue

        lines = content.split("\n")

        for name, pattern, severity, category, description, fix_steps in CODE_PATTERNS:
            for m in pattern.finditer(content):
                # Find line number
                line_num = content[:m.start()].count("\n") + 1
                sig = f"{name}:{path}:{line_num}"
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                # 3-line context
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                context = "\n".join(f"  {i+start+1}: {lines[i]}" for i in range(end - start))

                findings.append({
                    "severity": severity,
                    "category": category,
                    "title": f"Dangerous Code Pattern: {name}",
                    "description": description,
                    "fix_steps": fix_steps,
                    "affected_asset": path,
                    "line_number": line_num,
                    "metadata": {"context": context, "pattern": name},
                })

    return findings


def parse_code(content: str):
    try:
        tree = ast.parse(content)
        return tree
    except SyntaxError as e:
        print(f"Error parsing code: {e}")
        return None


def check_eval(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'eval':
            return True
    return False


async def scan_code_patterns_safe(files: list[dict]) -> list[dict]:
    findings = []
    seen_signatures = set()

    SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__", ".next"}
    SKIP_EXTS = {".min.js", ".map", ".png", ".jpg", ".gif", ".svg", ".pdf", ".zip"}

    for file_obj in files:
        path = file_obj.get("path", "")
        content = file_obj.get("content", "")

        if any(f"/{skip}/" in f"/{path}" or path.startswith(f"{skip}/") for skip in SKIP_DIRS):
            continue
        if any(path.endswith(ext) for ext in SKIP_EXTS):
            continue

        tree = parse_code(content)
        if tree is None:
            continue

        if check_eval(tree):
            findings.append({
                "severity": "critical",
                "category": "dangerous_code",
                "title": "Dangerous Code Pattern: eval() with variable input",
                "description": "Your code uses eval() with a dynamic value. If that value comes from user input, an attacker can execute any code they want on your server.",
                "fix_steps": "1. Remove eval() from your code\n2. Find a safer alternative — eval() is almost never necessary\n3. If evaluating math expressions, use a dedicated math library",
                "affected_asset": path,
                "line_number": 1,
                "metadata": {"context": content, "pattern": "eval() with variable input"},
            })

    return findings