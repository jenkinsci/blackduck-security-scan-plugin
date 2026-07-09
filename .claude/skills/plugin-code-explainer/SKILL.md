---
name: plugin-code-explainer
description: Deep code explanations for Black Duck Security Scan Jenkins Plugin. When a user asks "how does X work", "explain the flow", "walk me through", or "what happens when", this skill provides structured walkthroughs covering entry points, call chains, layer-by-layer logic, and design intent. Triggered via /plugin-code-explainer or when user asks for architecture/flow understanding, data flow tracing, or reasoning behind implementation choices. Use this skill whenever the user wants to understand WHY the code is designed a certain way, not just WHAT it does.
compatibility: Jenkins 2.492.3+
---

# Black Duck Plugin — Code Explainer

Structured explanations of code flows, architecture, and design reasoning for this Jenkins plugin.

---

## What to Explain

This skill addresses "how does X work?" questions about the plugin's architecture and execution flows.

### Core Entry Points
- **`SecurityScan.java`** (extension/): Jenkins step definition for both Freestyle and Pipeline jobs
- **`ScanInitializer.java`**: Extracts job config into scanParams map
- **`SecurityScanner.java`**: Orchestrator that runs the scan and handles results

### Key Flows to Know
1. **Job configuration → Scan execution**: UI config → `ScanInitializer` → `SecurityScanner` → `ToolsParameterService` → Bridge CLI
2. **Result handling**: Bridge execution → SARIF/diagnostic report → `IssueCalculator` → issue counts → `IssueAction` (build artifact)
3. **Credential resolution**: Job config credential ID → Jenkins credential store → `ScanCredentialsHelper` → service layer
4. **Report archiving**: Bridge output → `UploadReportService` → Jenkins artifacts

### Service Layer Organization
Under `service/`:
- **`ToolsParameterService`**: Builds CLI argument list, manages temp JSON input
- **`ParameterMappingService`**: Maps plugin config → Black Duck Bridge parameters
- **`scan/`**: Product-specific parameter builders (SCA, Polaris, Coverity)
- **`bridge/`**: Bridge CLI download and execution
- **`scm/`**: Git/SCM checkout and credential handling
- **`diagnostics/UploadReportService`**: Archives SARIF and diagnostic reports

### Global Utilities
Under `global/`:
- **`Utility`**: JSON parsing, path resolution, proxy setup, env var handling
- **`IssueCalculator`**: Parses scan-info.json → extracts issue counts and URLs
- **`ApplicationConstants`**: All string constants (keys, file paths, error messages)
- **`LoggerWrapper`**: Wraps Jenkins `TaskListener` for consistent logging

---

## How to Explain a Flow

### 1. Identify Entry Point

Find where the flow starts:
- Job trigger → `SecurityScan.java` (extension point)
- Manual explanation request → scan or step name (e.g., "how does the SCA scan work?")
- Configuration → `ScanInitializer.java`

### 2. Trace Call Chain

Follow method calls across files. For each file/method, list:
- **File and method name**
- **Responsibility** (one sentence: what it does)
- **Data it receives** (inputs)
- **Data it produces** (outputs)
- **Key logic** (if non-obvious)

Example:
```
1. `SecurityScan.java:perform()` 
   - Responsibility: Jenkins step entry point; coordinates scan setup and execution
   - Input: Job config, build environment
   - Output: Build result (success/failure)
   - Logic: Calls ScanInitializer to extract config, then SecurityScanner to run scan

2. `ScanInitializer.java:initializeScanParameters()`
   - Responsibility: Converts job UI configuration into Map<String, Object> scanParams
   - Input: Job config object, build context
   - Output: scanParams map with all config values
   - Logic: Reads credential IDs, product selection, URLs; resolves Jenkins variables
```

### 3. Explain Layer Logic (The Why)

For each significant step, explain:

- **What it does** (the code behavior)
- **Why it does it that way** (design intent):
  - Jenkins constraint (e.g., "credentials accessed via Jenkins API, not directly")
  - Security reasoning (e.g., "temp files created in workspace, not /tmp, for agent isolation")
  - Architectural choice (e.g., "parameters passed as JSON object not CLI args for type safety")
  - Performance reason (e.g., "Bridge downloaded once and cached, not per-build")

### 4. Highlight Key Files & Roles

Always call out which files are involved and what role they play:
- **Core orchestration**: `SecurityScanner.java`
- **Configuration extraction**: `ScanInitializer.java`
- **CLI argument building**: `ToolsParameterService.java`
- **Credential resolution**: `ScanCredentialsHelper.java`
- **Report handling**: `UploadReportService.java`, `IssueCalculator.java`

### 5. Surface Non-Obvious Design Decisions

Explain why the code is structured this way:

- **Why temp JSON instead of CLI args?** Type safety + reduces injection risk + easier to debug
- **Why lazy credential resolution?** Jenkins credential store API requires `Run` context
- **Why separate `ScanInitializer` class?** Encapsulates config extraction from execution; testable in isolation
- **Why `EnvVars` instead of `System.getenv()`?** Jenkins `EnvVars` includes build-injected variables (like `$WORKSPACE`), system env, and overrides
- **Why `FilePath` instead of `File`?** FilePath works across Jenkins agents (master/slave safety); File only on master
- **Why `TaskListener` for logging?** Jenkins logging goes to console output; `System.out` would be lost in agent context

---

## Output Format

Produce explanations in this structure:

### 1. Plain-English Summary (1 paragraph)

Brief overview of what the feature/flow does and why it matters.

Example:
> The scan execution flow coordinates three phases: (1) configuration extraction from the Jenkins job, (2) building CLI arguments from that configuration and executing the Bridge CLI tool, and (3) parsing and archiving the resulting scan reports. The plugin acts as an orchestration layer; the Bridge CLI itself performs the actual security scanning (SCA, Polaris, or Coverity).

### 2. Step-by-Step Flow (numbered list)

Each step includes file name in backticks, method name, brief description, and inputs/outputs.

```
1. `SecurityScan.java` : perform()
   - Coordinates job setup and scan execution

2. `ScanInitializer.java` : initializeScanParameters()
   - Extracts job config into scanParams map

3. `SecurityScanner.java` : runScanner()
   - Orchestrates parameter building, Bridge invocation, and result handling

4. `ToolsParameterService.java` : buildCommandLineArgs()
   - Builds CLI argument list from scanParams

5. [Bridge CLI invocation via Launcher]
   - Executes: /path/to/bridge [args]
   - Generates: scan-info.json, sarif.json, diagnostic reports

6. `IssueCalculator.java` : getIssuesUrl()
   - Parses scan-info.json for issue counts and results URL

7. `UploadReportService.java` : archiveReports()
   - Archives SARIF and diagnostic reports as Jenkins artifacts
```

### 3. Key Design Decisions Section

Explain *why* the architecture is the way it is. Each decision should include:
- What was chosen
- Why (constraints, security, Jenkins patterns, etc.)

Example:
```
## Key Design Decisions

**Separate ScanInitializer class:** Encapsulates configuration extraction from scan execution. Allows testing config parsing in isolation without mocking the entire Jenkins build context.

**Temp JSON for Bridge input:** Bridge parameters passed via temporary JSON file (not CLI args) because: (a) type safety, (b) easier to debug (inspect the JSON), (c) reduces shell injection risk, (d) supports nested/complex config.

**FilePath for file operations:** All file operations use Jenkins `FilePath` (not `java.io.File`) because FilePath abstracts agent boundaries — code works the same on master and distributed agents.

**LazyCredentialResolution:** Credentials from Jenkins store are resolved late (in service layer, not in ScanInitializer) because the Jenkins credential API requires `Run` context, which is available during build execution but not during config loading.
```

### 4. Flow Summary Diagram

End with a simple ASCII diagram or numbered chain showing the overall flow:

```
SecurityScan (entry)
  ↓
ScanInitializer (extract config)
  ↓
SecurityScanner (orchestrate)
  ├→ ToolsParameterService (build CLI args)
  ├→ Launcher (execute Bridge CLI)
  ├→ IssueCalculator (parse results)
  └→ UploadReportService (archive artifacts)
```

Or as a simple chain:
```
Entry: SecurityScan → Extract: ScanInitializer → Execute: SecurityScanner → 
Build: ToolsParameterService → Run: Bridge CLI → Parse: IssueCalculator → 
Archive: UploadReportService
```

---

## Example Questions & How to Answer

### Q: "How does the scan parameter flow work?"

**Answer structure:**
1. Summary: "Parameters flow from job config → service layer → CLI execution. The plugin uses a map-based approach for flexibility and to decouple config from execution logic."
2. Steps: ScanInitializer extracts → SecurityScanner receives map → ToolsParameterService builds args → Bridge executes
3. Design decisions: Why a map? Type safety, easy to validate, decouples config structure from CLI structure. Why not direct args? Reduces injection risk, easier to test.
4. Diagram: Config → ScanInitializer map → SecurityScanner → ToolsParameterService args → CLI

### Q: "Why does credential resolution happen in the service layer, not ScanInitializer?"

**Answer structure:**
1. Summary: "Credential resolution is deferred to the service layer (during scan execution) because Jenkins credential APIs require build-time context."
2. Steps: ScanInitializer stores credential ID as string → SecurityScanner triggers execution → Service classes (e.g., BlackDuckSCAParametersService) call CredentialsProvider.findCredentialById() → credentials resolved
3. Design decisions: Lazy resolution = credentials only accessed when needed, with correct Jenkins context. Earlier resolution = API call would fail (no Run context yet).
4. Diagram: Config ID → ScanInitializer → Build time → Service layer → CredentialsProvider → Actual credential

---

## Do NOT Explain

- Code formatting details (Spotless handles that)
- Performance optimization ideas (unless user explicitly asks)
- How to write new code (use `/plugin-code-review` or `/plugin-code-generator`)
- Security vulnerabilities and audit findings (use `/plugin-security-review` for credential/injection/masking issues)
- Test harness setup (unless explaining existing test patterns)
