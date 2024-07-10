## sam-cli: Vulnerability Analyzer for Lua Smart Contracts
sam-cli is a powerful tool designed to assist developers in identifying vulnerabilities within Lua smart contracts. Leveraging static analysis techniques, SAM CLI detects potential security issues that could compromise the integrity and functionality of smart contracts.


### Steps to Use SAM CLI
- Clone the SAM CLI Repository

```bash
Copy code
git clone https://github.com/krishvsoni/sam-cli
cd sam-cli
```
- Analyze Lua Smart Contracts
- Use SAM CLI to analyze your Lua smart contract file (filepath.lua). Replace filepath.lua with the path to your Lua code file.

```bash
sam path-to-lua-file --generate-report
```

This command performs static analysis on the specified Lua smart contract file and generates a detailed vulnerability report in HTML format (report.html).

<img width="1241" alt="image" src="https://github.com/krishvsoni/sam-cli/assets/67964054/b0cb90b8-8635-4620-b9c0-3bc44652a5e0">
