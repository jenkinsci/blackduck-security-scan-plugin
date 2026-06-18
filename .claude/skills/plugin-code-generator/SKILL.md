---
name: plugin-code-generator
description: Generates production-ready code for the Black Duck Security Scan Jenkins Plugin. Drives discovery of existing patterns, designs changes against codebase conventions, generates complete implementation with tests, and audits for breaking changes. Use when user says "implement", "implement feature", "implement this", "add support for", "add parameter", "add scan product", "write the code for", or any request to build new plugin functionality. Triggered via /plugin-code-generator.
compatibility: Jenkins 2.492.3+
---

# Plugin Code Generator

Generates plugin code through four phases: Discovery (read codebase), Design (map changes), Implementation (complete code), Verification (validate backward compatibility).

## Trigger

Use when implementing plugin functionality: add parameters, scan products, credential types, CLI flags, or report handling.

## Four-Phase Workflow

### Phase 1: Discovery — Context Gathering

**Your goal:** Build complete mental model of the current codebase before writing a single line.

1. **Identify relevant files** based on the user's request type:
   - New parameter → `ApplicationConstants.java`, `ToolsParameterService.java`, `ParameterMappingService.java`
   - New scan product → `SecurityProduct.java` (enum), `ScanParametersService.java`, `SecurityScanner.java`
   - New UI config field → `extension/SecurityScan.java`, `extension/freestyle/`, `extension/pipeline/`, Jelly files under `src/main/resources/`
   - Credential-related → `Utility.java`, `extension/global/`, credential resolution patterns
   - Report/artifact handling → `UploadReportService.java`, `IssueCalculator.java`, bridge integration points

2. **Read relevant files completely.** Don't skim. Use `grep` to find:
   - Method signatures (to ensure backward compatibility)
   - Enum values (to understand naming patterns)
   - Constructor/setter patterns (Jenkins serialization rules)
   - Existing test patterns (copy test structure, not invent new patterns)

3. **Identify insertion points.** Document:
   - Which methods need new logic
   - Which classes need new fields
   - Which constants need new entries
   - Exact line numbers or method names where changes belong

**Output for Phase 1:**
```
## Discovery Summary
- Files read: [list with brief purpose]
- Insertion points: [method/class/field with reason]
- Codebase pattern observed: [key naming pattern, architecture principle identified]
```

---

### Phase 2: Design — Reasoning & Architecture

**Your goal:** Prove you understand the codebase deeply before implementing.

1. **Explain the reference pattern.** Find the closest existing feature and explain how it's currently implemented end-to-end:
   - Example: "Coverity product support is implemented via: (1) `SecurityProduct.COVERITY` enum, (2) Coverity-specific parameters in `ParameterMappingService`, (3) branch in `SecurityScanner.runScanner()` to handle Coverity-specific report formats, (4) tests in `CoveritySecurityScannerTest`."

2. **Map the full change surface.** List every file that will change and why:
   ```
   | File | Change | Reason |
   |------|--------|--------|
   | ApplicationConstants.java | Add POLARIS_KEY constant | Centralize all string keys per codebase convention |
   | SecurityProduct.java | Add POLARIS to enum | Define new product type |
   ```

3. **Identify reusable patterns.** Commit explicitly:
   - "I will use `@DataBoundSetter` for new UI fields because existing config fields (e.g., in `SecurityScan.java`) follow this pattern for Jenkins serialization."
   - "I will pass sensitive data via Jackson POJO serialization (not CLI args) because the plugin isolates credentials from process-visible command lines."
   - "I will add constants to `ApplicationConstants.java` because all string keys are centralized there."
   - "I will update `ParameterMappingService` alongside any new product enum because parameter mapping is product-specific."

4. **Flag risks and constraints.**
   - Jenkins serialization rules: `@DataBoundConstructor` + `@DataBoundSetter` for config objects
   - Jelly view naming: must match descriptor class name (e.g., `MyDescriptor.java` → `MyDescriptor.jelly`)
   - JSON parsing: use Jackson `JsonNode`, never `org.json`
   - Logging: use `LoggerWrapper`, never raw `Logger` or `System.out`
   - Spotless formatting: must pass `./mvnw spotless:apply`

**Output for Phase 2:**
```
## Design Reasoning
- Reference pattern: [ClassName and brief explanation]
- Full change surface:
  | File | Change | Reason |
  |------|--------|--------|
- Reusable patterns identified: [list with "why" for each]
- Risks/constraints: [none, or list with mitigation]
```

---

### Phase 3: Implementation — Production Code

**Your goal:** Production-ready code with no guesswork, no TODOs, no gaps.

1. **Generate complete code.** For every file changed:
   - Output the **full modified file** (not snippets)
   - Clearly mark new code vs. existing
   - Include all imports, all method bodies
   - No ellipsis shortcuts (`...`)

2. **Follow codebase standards without exception:**
   - Constants: `public static final String` in `ApplicationConstants.java`
   - Logging: `LoggerWrapper` calls only (see `Utility.java` for masking pattern)
   - Sensitive data: wrapped in `Utility.maskSensitiveData()` before any log output
   - JSON: Jackson `JsonNode` for parsing (see `IssueCalculator.java` examples)
   - Jenkins config: `@DataBoundConstructor` + `@DataBoundSetter`
   - Jelly views: `src/main/resources/` folder, matching descriptor class name
   - Package: `io.jenkins.plugins.security.scan.*`
   - Java version: 11+ compatible (no newer language features)

3. **Generate JUnit 5 + Mockito tests.** For all new logic:
   - Happy path (feature works as intended)
   - Null/empty/missing input handling
   - Edge cases specific to the feature
   - Use existing test classes as templates (e.g., `ParameterMappingServiceTest.java`)
   - Mock Jenkins constructs: `Run`, `TaskListener`, `Launcher`, `FilePath`, `EnvVars`

**Output for Phase 3:**
```
## Implementation

### [FileName]
[Full file content, clearly labeled with line ranges or section headers]

### Tests
[Complete JUnit 5 test class(es) — ready to `./mvnw test`]
```

---

### Phase 4: Verification — Impact Analysis

**Your goal:** Prove the change doesn't break anything.

1. **Breaking change audit:**
   - Trace every call site of methods you modified
   - Verify method signatures are backward compatible (or all callers updated)
   - Check existing tests — would any fail with the new code?
   - Trace `SecurityScanner.runScanner()` end-to-end with the new feature enabled
   - Verify `ScanInitializer` parameter extraction handles new fields without breaking old ones

2. **Create a breaking-change checklist:**
   ```
   | Flow | Status | Notes |
   |------|--------|-------|
   | Freestyle job scan (existing product) | Safe | No changes to parameter resolution |
   | Pipeline step (new parameter optional) | Safe | New field is @DataBoundSetter with default |
   | Global proxy config | Review | Modified Utility.setupProxyParameters() — verify all call sites |
   ```

3. **Identify manual verification steps** for the developer:
   - "Run `./mvnw test` to verify all tests pass"
   - "Manually test: create Freestyle job with new feature disabled, then enabled"
   - "Integration test: spin up `docker-compose up` and create a test job"

**Output for Phase 4:**
```
## Impact Analysis
[Checklist table showing each existing flow and status]

## Manual Verification Checklist
- [ ] Run `./mvnw clean install` — code formats and builds
- [ ] Run `./mvnw test` — all tests pass
- [ ] Test on existing product flows
- [ ] [Feature-specific verification]

## Try It Locally (Optional)
```bash
./mvnw -Dtest=NewFeatureTest test
./mvnw hpi:run  # Jenkins at https://localhost:8080/jenkins
```
```

---

## Codebase Conventions (Non-Negotiable)

- **Main package:** `io.jenkins.plugins.security.scan`
- **Jenkins baseline:** 2.492.3 — no newer APIs
- **String constants:** All in `ApplicationConstants.java` (no inline strings)
- **Logging:** `LoggerWrapper` only
- **Secrets masking:** `Utility.maskSensitiveData()` for tokens, passwords, URLs in logs
- **JSON parsing:** Jackson `JsonNode` (no `org.json`)
- **Jenkins config:** `@DataBoundConstructor` + `@DataBoundSetter` for all config fields
- **Jelly views:** `src/main/resources/` with class-name-matching convention
- **Formatting:** Pass `./mvnw spotless:apply`
- **Tests:** JUnit 5 + Mockito, following existing patterns in `src/test/java/`

---

## Example Workflow

User: "Add support for a new scan product called Xyzwv."

**Phase 1 (Discovery):** Read `SecurityProduct.java` (current enum), `ParameterMappingService.java` (parameter building), `SecurityScanner.java` (product routing), existing product tests.

**Phase 2 (Design):** Explain how Coverity is currently supported end-to-end, map all changes (add enum, add parameter mappings, add scanner routing, add tests).

**Phase 3 (Implementation):** Output complete `SecurityProduct.java`, modified `ParameterMappingService`, modified `SecurityScanner`, complete test class.

**Phase 4 (Verification):** Verify existing products still work, trace `SecurityScanner.runScanner()` with Xyzwv enabled, create backward-compatibility checklist.

---

## Core Principles

- Read files directly; verify all claims against actual repository code.
- Ship production-ready code only; no TODOs or placeholders.
- Flag unclear patterns and request clarification before implementing.
