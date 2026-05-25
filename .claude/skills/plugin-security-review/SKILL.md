---
name: plugin-security-review
description: Security audit for Black Duck Security Scan Jenkins Plugin. Audit credential handling, CLI parameter injection, log masking, input validation, JSON safety, and SCM/artifact security. Use when user asks for security review, security audit, or to check for vulnerabilities in this plugin repo — especially when changes touch credential, parameter, or logging code. Triggered via /plugin-security-review. Do NOT use the generic security-review skill for this repo; use this one instead.
compatibility: Jenkins 2.492.3+
---

# Black Duck Plugin — Security Review

Security-specific audit for Jenkins plugin trust boundaries. Focus: credential isolation, CLI injection, log masking, input validation.

---

## What to Check

### 1. Credential Handling (Highest Priority)

**Source of Truth:** Jenkins credential store ONLY. Never:
- Embed in config files
- Pass via environment variables
- Log (masked or not)
- Pass via CLI args (use JSON instead)

Check these files first:
- `extension/global/ScannerGlobalConfig.java` — credential loading
- `service/scan/blackducksca/BlackDuckSCAParametersService.java` — token handling
- `service/scan/coverity/CoverityParametersService.java` — password handling
- `service/scan/polaris/PolarisParametersService.java` — token handling
- `service/scan/srm/SRMParametersService.java` — token handling
- `service/scm/github/GithubRepositoryService.java` — SCM token handling
- `global/ScanCredentialsHelper.java` — credential resolution

**Pattern to enforce:**
```java
// SAFE: Credential from store, used in Jackson POJO only
String credentialId = config.getBlackDuckCredentialId();
BaseStandardCredentials cred = CredentialsProvider.findCredentialById(credentialId, ...);
String token = ((StringCredentials) cred).getSecret().getPlainText();
blackDuckSCA.setToken(token);  // Object field, not string
String json = mapper.writeValueAsString(blackDuckSCA);  // Jackson serializes safely
Files.write(tempFile, json.getBytes());
```

**Red flags:**
- `envVars.put("TOKEN", ...)` — DANGER: credentials leaked to Jenkins logs
- `commandLineArgs.add("--token=" + token)` — DANGER: visible in process list + logs
- `logger.info("Token: " + token)` — DANGER: in console output
- Token in exception message
- Token in temp file without cleanup

---

### 2. CLI Parameter Injection

**Risk:** Job config → CLI args unsanitized.

Check: Do user-input parameters reach Bridge CLI?

**Pattern to enforce:**
```java
// SAFE: Separate args (quoting handled by launcher)
commandLineArgs.add("--url");
commandLineArgs.add(blackduckUrl);

// SAFE: OR validate + quote for string concat
if (!isValidUrl(blackduckUrl)) throw new PluginExceptionHandler("Invalid URL");
commandLineArgs.add("--url=" + Util.escape(blackduckUrl));
```

**Red flags:**
- `commandLineArgs.add("--url=" + url)` without validation/escaping
- User paths/URLs interpolated into args
- Special chars (`;`, `|`, `&`, backticks, `$`) in parameters not escaped

---

### 3. Log Masking

**Rule:** No token, password, or auth URL in ANY log output.

Check: Before logging CLI args or parameters, mask sensitive patterns:
- `--token=<value>` → `--token=***`
- `--password=<value>` → `--password=***`
- `--apikey=<value>` → `--apikey=***`
- `http://user:password@host` → `http://user:***@host`
- `http://host?token=xxx` → `http://host?token=***`

Check these files:
- `global/Utility.java` — CLI arg building + proxy masking
- `service/ToolsParameterService.java` — parameter logging
- `SecurityScanner.java` — execution logging
- Any file with `logger.info()` of scanParams or args

**Pattern to enforce:**
```java
// SAFE: Mask before logging
List<String> maskedArgs = maskSensitiveArgs(commandLineArgs);
logger.info("Executable command line: " + maskedArgs);

private static List<String> maskSensitiveArgs(List<String> args) {
    return args.stream()
        .map(arg -> arg.matches("^--(token|password|apikey)=.*")
            ? arg.replaceAll("=.*", "=***")
            : arg)
        .collect(Collectors.toList());
}
```

**Red flags:**
- `logger.info("Command: " + commandLineArgs)` — unmasked
- `logger.debug("Proxy: " + proxyUrl)` — if URL contains `user:pass@`
- `logger.info("Scan params: " + scanParams)` — map likely contains tokens
- Exception messages with credential context: `"Auth failed for user:password"`

---

### 4. Input Validation

**Rule:** User-controlled inputs validated before use.

Check job config parameters:
- **Credentials:** ID must exist in Jenkins credential store
  ```java
  String credId = config.getBlackDuckCredentialId();
  if (isStringNullOrBlank(credId)) {
      throw new PluginExceptionHandler("Credential ID not configured");
  }
  BaseStandardCredentials cred = CredentialsProvider.findCredentialById(credId, ...);
  if (cred == null) {
      throw new PluginExceptionHandler("Credential '" + credId + "' not found");
  }
  ```

- **URLs:** Valid format + reachable (or skip reachability if offline OK)
  ```java
  try {
      new URL(blackduckUrl);  // Throws if invalid format
  } catch (MalformedURLException e) {
      throw new PluginExceptionHandler("Invalid Black Duck URL");
  }
  ```

- **Paths:** Canonicalized, no `../` traversal
  ```java
  Path p = Paths.get(userPath).toAbsolutePath().normalize();
  if (!p.startsWith(workspace.toAbsolutePath())) {
      throw new PluginExceptionHandler("Path escapes workspace");
  }
  ```

- **Enums:** Check against known values
  ```java
  String product = config.getSecurityProduct();
  if (SecurityProduct.fromString(product) == null) {
      throw new PluginExceptionHandler("Unknown product: " + product);
  }
  ```

- **Numbers:** Non-negative, bounded
  ```java
  int timeout = config.getTimeout();
  if (timeout <= 0 || timeout > 3600) {
      throw new PluginExceptionHandler("Timeout must be 1-3600 seconds");
  }
  ```

**Red flags:**
- Using credentialId without checking `CredentialsProvider.findCredentialById()`
- URL passed to Bridge without format validation
- User path used directly in FilePath operations
- Enum values compared via string (use enum comparison)

---

### 5. JSON Safety

**Rule:** Untrusted JSON (Bridge output) parsed defensively.

Check: `Utility.parseJsonFile()`, `IssueCalculator` — parsing scan-info.json and SARIF.

**Pattern to enforce:**
```java
// SAFE: Validate structure
JsonNode root = mapper.readTree(file);
if (!root.has("issues") || !root.get("issues").isArray()) {
    throw new PluginExceptionHandler("Invalid scan-info.json format");
}
root.get("issues").forEach(issue -> {
    if (!issue.has("rule") || !issue.has("severity")) {
        throw new PluginExceptionHandler("Malformed issue in scan-info.json");
    }
});
```

**Red flags:**
- `mapper.readTree()` without structure validation
- Accessing fields without `.has()` check (throws on missing)
- Polymorphic deserialization of untrusted JSON
- No bounds on array/object size

---

### 6. SCM & Repository Security

**Rule:** Git URLs from Jenkins SCM sources only, not user input.

Check: `service/scm/` classes.

**Pattern to enforce:**
```java
// SAFE: URL from Jenkins SCM source (managed, not user-input)
String repoUrl = scmSource.getRepositoryUrl();
// OR whitelist validation if user can input
List<String> allowed = Arrays.asList("github.com", "internal-git.example.com");
URL url = new URL(repoUrl);
if (!allowed.contains(url.getHost())) {
    throw new PluginExceptionHandler("Repository host not allowed");
}

// SAFE: Path canonicalized
Path clonePath = Paths.get(workspace).toAbsolutePath().normalize();
if (!clonePath.startsWith(workspaceRoot)) {
    throw new PluginExceptionHandler("Clone path escapes workspace");
}
```

**Red flags:**
- `git clone <user-supplied-url>`
- SSH keys left on disk unencrypted or not cleaned up
- Branch/tag names from user input without validation (could be `; rm -rf`)
- Repository paths not canonicalized (../../ traversal risk)

---

### 7. Artifact/Report Safety

**Rule:** Diagnostic and SARIF reports cannot contain credentials or source code with secrets.

Check: `service/diagnostics/UploadReportService.java`.

**Pattern to enforce:**
```java
// SAFE: Only intended reports archived
List<String> allowed = Arrays.asList(
    "scan-info.json",
    "*.sarif",
    "report-summary.txt"
);
for (FilePath report : workspace.list()) {
    if (!allowed.stream().anyMatch(report.getName()::matches)) {
        report.delete();  // Exclude logs, temp files, unfiltered output
    }
}
```

**Red flags:**
- `workspace.child("*")` or `workspace.child("logs/*")` archived
- Full Bridge output (including debug logs with tokens) archived
- Diagnostic zip includes source code
- Report filenames encode secrets: `scan-<token>.sarif`

---

### 8. Exception Handling

**Rule:** Exceptions don't leak credential context or fail silently on security checks.

**Pattern to enforce:**
```java
// SAFE: No credential in exception
try {
    authenticate(user, password);
} catch (AuthException e) {
    throw new PluginExceptionHandler("Authentication failed");
}

// SAFE: Explicit security-relevant error handling
try {
    validateCertificate(cert);
} catch (CertificateException e) {
    if (config.isInsecureSSLAllowed()) {
        logger.warn("SSL certificate validation disabled by configuration");
    } else {
        throw new PluginExceptionHandler("Certificate validation failed");
    }
}
```

**Red flags:**
- `catch (Exception e) { logger.warn(...); }` — silent swallow of security checks
- `throw new PluginExceptionHandler("Auth failed: " + password)`
- Network timeouts not caught (causes build hang)

---

## Review Checklist (Quick)

- [ ] **Credentials:** Only from Jenkins store, never in logs/args/env vars
- [ ] **CLI args:** Validated + escaped OR passed as separate args (launcher handles quoting)
- [ ] **Log masking:** `--token=`, `--password=`, proxy URLs masked before logging
- [ ] **Input validation:** Credentials exist, URLs parse, paths canonicalized, enums checked
- [ ] **JSON safety:** Bridge output structure validated
- [ ] **SCM security:** Repository URLs from Jenkins, paths canonicalized
- [ ] **Artifacts:** Only intended reports archived, no logs or source with secrets
- [ ] **Exceptions:** No credential context, security checks not silently caught

---

## Example Findings

```
service/ToolsParameterService.java:42: --token= CLI arg, pass via JSON instead.
global/Utility.java:156: proxy URL logged unmasked, use replaceAll("://.*@", "://***@").
SecurityScanner.java:78: commandLineArgs logged, mask --password before logging.
service/scan/BlackDuckSCAParametersService.java:35: token from envVars, use Jenkins credential store.
service/diagnostics/UploadReportService.java:91: workspace.child("*") archives logs, filter to intended reports only.
extension/global/ScannerGlobalConfig.java:22: credentialId not validated, check findCredentialById exists.
```

---

## Trust Boundaries in This Plugin

Unlike web apps, Jenkins plugins have NO:
- User authentication layer
- Web endpoints / HTTP handlers
- XSS, CSRF, or client-side injection

But DO have:
- Job config parameters (user-controlled) → CLI execution (untrusted)
- Jenkins credential store (trusted) → Bridge CLI (untrusted by design)
- Build workspace (shared across users/agents) — secrets leak risk
- Console logs (visible to job readers) — masking critical
- Artifacts (downloadable) — no embedded secrets

---

## Do NOT Check

- Code style/formatting (Spotless enforces)
- Performance
- Architecture (use `/plugin-code-review`)
- Test coverage (use `/plugin-code-review`)
- Comments/documentation
