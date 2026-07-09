---
name: plugin-code-review
description: Code quality review for Black Duck Security Scan Jenkins Plugin. Audit patterns, test coverage, exception handling, Jackson/LoggerWrapper usage, and architecture alignment. Use when user asks to review code, a PR, or a diff in this plugin repo — especially when changes touch service/, extension/, or global/ code. Triggered via /plugin-code-review. Do NOT use the generic code-review skill for this repo; use this one instead.
compatibility: Jenkins 2.492.3+
---

# Black Duck Plugin — Code Review

Correctness and pattern audit for this Jenkins plugin repo only. NOT for security — use `/plugin-security-review` for credential/injection/masking issues.

---

## What to Check

### 1. Pattern Adherence

**Service Layer (service/):**
- [ ] New service classes extend from existing base patterns (or justify why not)
- [ ] Dependency injection via constructor, not field injection
- [ ] Methods accept `TaskListener` for logging (never `System.out`)
- [ ] Return types are immutable or explicitly documented as mutable

**Jackson JSON Serialization (everywhere):**
- [ ] All Bridge input built via POJO → `ObjectMapper.writeValueAsString()`, not string concat
- [ ] Bridge output parsed via `mapper.readTree()` with structure validation
- [ ] No custom deserializers without explicit type whitelist

**Logging (LoggerWrapper):**
- [ ] All logs use `LoggerWrapper`, never raw Jenkins `TaskListener`
- [ ] Log level appropriate (INFO for user-facing, DEBUG for internals)
- [ ] No logged parameters that might contain sensitive data (use `/plugin-security-review` for masking audit)

**Exception Handling:**
- [ ] New exceptions inherit from `PluginExceptionHandler` or explicit throw rationale
- [ ] Try-finally blocks for resource cleanup (temp files, streams)
- [ ] No silent catch-all blocks (`catch (Exception e) { }`)

**FilePath Usage (Jenkins standard):**
- [ ] Remote operations use `FilePath`, not `File` directly
- [ ] Path operations respect agent boundaries (master/slave safety)
- [ ] No hardcoded `/tmp` or absolute paths without canonicalization

---

### 2. Test Coverage

Check tests match production code:
- [ ] New service classes have corresponding test class (e.g., `FooService` → `FooServiceTest`)
- [ ] Core flows tested (happy path + 1-2 error cases)
- [ ] Mocks used appropriately (Jenkins `Run`, `TaskListener`, `Launcher`, not external services)
- [ ] Edge cases covered: null inputs, empty collections, boundary values

**Excluded from coverage (expected, don't test):**
- Extension classes (`extension/`, `extension/freestyle/`, `extension/pipeline/`)
- `SecurityScanner`, `SCMRepositoryService` (complex orchestration, hard to mock)
- Input classes (POJOs)

---

### 3. Enum & Config Classes

- [ ] SecurityProduct enum covers all products (BLACKDUCKSCA, POLARIS, COVERITY, SRM)
- [ ] Config classes immutable or documented mutation rules
- [ ] Getters/setters follow Jenkins convention (never raw field access in Freestyle/Pipeline)

---

### 4. Parameter Flow

Trace scanParams map from UI config → CLI args:

- [ ] ScanInitializer: Extracts config into Map<String, Object> scanParams
- [ ] ToolsParameterService: Validates and builds CLI args (audit for injection risks in `/plugin-security-review`)
- [ ] ParameterMappingService: Maps plugin config → Black Duck Bridge parameters
- [ ] No intermediate transformation loses type safety (should be type-enforced at boundary)

---

### 5. Report Handling (UploadReportService, IssueCalculator)

- [ ] SARIF reports: filename matches selected product (SCA → sarif.json, Polaris → polaris-sarif.json)
- [ ] IssueCalculator: Parses scan-info.json correctly for all products
- [ ] Artifact archiving: only intended reports archived, temp files excluded
- [ ] Report paths: no hardcoded agent-specific paths

---

### 6. SCM Integration (service/scm/)

- [ ] Git operations use FilePath (not File)
- [ ] Checkout credentials resolved from Jenkins credential store
- [ ] Branch/tag validation: no arbitrary ref injection (audit security in `/plugin-security-review`)
- [ ] SCM failure doesn't cascade without explicit control

---

### 7. Code Style & Naming

- [ ] Variable names: clear intent (`credentialId` not `id`, `scanResults` not `data`)
- [ ] Method names: verb + noun (`buildCommandLineArgs`, not `build`)
- [ ] Constants in `ApplicationConstants`: no magic strings in code
- [ ] No commented-out code unless justified (e.g., "workaround for XYZ bug #123")

---

### 8. Spotless Compliance

- [ ] Code runs through `./mvnw spotless:apply` (enforced, but check for style violations pre-commit)
- [ ] Imports: single-type imports, no wildcard (except static for test assertions)
- [ ] Line length: 120 chars (plugin's limit, not Java default 100)

---

## Common Findings

| Issue | Fix |
|---|---|
| New service has no test class | Add `FooServiceTest.java` in `src/test/java/` |
| Logging with raw `TaskListener` | Use `LoggerWrapper.getLogger()` |
| Parameter built via string concat | Use Jackson ObjectMapper + POJO |
| Exception caught silently | Either log + rethrow, or document why silent |
| File operations on `File` in multi-agent job | Replace with `FilePath` |
| Hardcoded `/tmp` path | Use Jenkins temp dir: `workspace.tmp/` |
| Large if-else for product logic | Consider `SecurityProduct` enum switch |
| New product enum added, but ParameterMappingService unchanged | Add product-specific mappings to `ParameterMappingService` |

---

## Review Flow

1. Read PR diff
2. Identify changed files (service/, extension/, global/)
3. Check patterns above for each file
4. Output one-liner findings: `file:line: issue. fix.`

---

## Example Findings

```
service/ToolsParametersService.java:47: URL built via string concat, use Jackson POJO.
extension/freestyle/FooBuilder.java:23: No corresponding test class FooBuilderTest.java.
global/Utility.java:100: Raw TaskListener log, use LoggerWrapper.
service/scm/GitService.java:15: File operations, use FilePath for agent safety.
```

---

## Do NOT Check

- Security issues (use `/plugin-security-review`)
- Code formatting details (Spotless handles that)
- Performance optimization (unless obvious bug)
- Documentation/comments (unless missing critical context)
