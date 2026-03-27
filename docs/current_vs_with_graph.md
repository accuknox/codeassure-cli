current vs. with graph:

Current Output (what the user gets today)

  {
    "check_id": "dangerous-subprocess-use-audit",
    "path": "checkov/checkov.py",
    "start": { "line": 100 },
    "extra": {
      "message": "Detected subprocess function 'run' without a static string...",
      "severity": "WARNING"
    },
    "verification": {
      "verdict": "true_positive",
      "is_security_vulnerability": true,
      "confidence": "high",
      "reason": "The code uses subprocess.run() with shell=True and string
                 interpolation of user-controllable variables (url, branch,
                 token, repo_name) without validation, enabling command injection.",
      "evidence": [
        { "location": "checkov/checkov.py:100" }
      ]
    }
  }

  What does the user see? A verdict and a reason string. To understand the actual
  vulnerability, they have to:
  1. Open checkov.py
  2. Go to line 100
  3. Manually trace where self.branch, url, token come from
  4. Scroll to line 148-158 to find the env var entry point
  5. Mentally build the data flow in their head

  For a senior security engineer, that's fine. For a developer triaging 356 findings, it's
  slow and error-prone.

  ---
  With Graph (what the user would get)

  {
    "check_id": "dangerous-subprocess-use-audit",
    "path": "checkov/checkov.py",
    "start": { "line": 100 },
    "verification": {
      "verdict": "true_positive",
      "is_security_vulnerability": true,
      "confidence": "high",
      "reason": "Command injection via shell=True with unsanitized environment
                 variables interpolated into git clone command.",
      "evidence": [
        { "location": "checkov/checkov.py:100" },
        { "location": "checkov/checkov.py:150" }
      ],
      "graph": {
        "summary": "Environment variables → class attributes → f-string →
  subprocess.run(shell=True)",
        "mermaid": "graph LR\n  ...",
        "nodes": [ ... ],
        "edges": [ ... ]
      }
    }
  }

  The mermaid field renders as:

   ┌─────────────────────────────┐
   │  __main__ (line 148-158)    │
   │                             │
   │  os.environ.get("branch") ──┼──┐
   │  os.environ.get("url") ─────┼──┤
   │  os.environ.get("token") ───┼──┤  UNTRUSTED
   │  os.environ.get("repo_type")┼──┤  INPUTS
   │  os.environ.get("framework")┼──┤
   └─────────────────────────────┘  │
                                    │
                                    ▼
   ┌─────────────────────────────────────────────┐
   │  run(branch=..., url=..., token=...)        │
   │  → CheckovRun(kwargs).main()                │
   │                                   line 12   │
   └──────────────────┬──────────────────────────┘
                      │
                      ▼
   ┌─────────────────────────────────────────────┐
   │  CheckovRun.run()                 line 72   │
   │                                             │
   │  url = self.url.split(...)        line 80   │
   │  repo_name = self.url.split(...) line 81   │
   │  token = f"...:{self.token}"      line 83   │  NO SANITIZATION
   │                                             │
   │  ┌─────────────────────────────────────┐    │
   │  │ ⚠ VULNERABILITY (line 100-101)     │    │
   │  │                                     │    │
   │  │ subprocess.run(                     │    │
   │  │   f"git clone -b {self.branch}      │    │
   │  │     https://{token}@{url}           │    │
   │  │     /repos/{repo_name}",            │    │
   │  │   shell=True  ← DANGEROUS          │    │
   │  │ )                                   │    │
   │  └─────────────────────────────────────┘    │
   │                                             │
   │  Same pattern repeats:                      │
   │  ⚠ subprocess.run(                         │
   │    f"checkov -d /repos                      │
   │      --framework {self.framework}...",      │
   │    shell=True)              line 120-121    │
   └─────────────────────────────────────────────┘

  And the Mermaid version (renderable in GitHub, VS Code, Jira, web UIs):

  graph TD
      A["os.environ.get('branch')<br/>os.environ.get('url')<br/>os.environ.get('token')<br/><
  i>line 150-153</i>"] -->|"no validation"| B
      B["run(branch, url, token)<br/><i>line 12</i>"] -->|"stored as self.*"| C
      C["self.branch, self.url<br/>self.token<br/><i>line 80-87</i>"] -->|"f-string
  interpolation"| D
      D["⚠ subprocess.run(<br/>f'git clone -b
  {self.branch}<br/>https://{token}@{url}...',<br/>shell=True)<br/><i>line 100</i>"]
      C -->|"f-string interpolation"| E
      E["⚠ subprocess.run(<br/>f'checkov
  --framework<br/>{self.framework}...',<br/>shell=True)<br/><i>line 120</i>"]

      style A fill:#6cf,stroke:#036,color:#000
      style D fill:#f66,stroke:#900,color:#000
      style E fill:#f66,stroke:#900,color:#000

  ---
 