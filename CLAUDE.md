# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Run local Jenkins with plugin hot-deployed (port 8080)
./mvnw hpi:run

# Build (skip tests)
./mvnw clean install -DskipTests

# Build with tests
./mvnw clean install

# Run all tests
./mvnw test

# Run a single test class
./mvnw test -Dtest=ParameterMappingServiceTest

# Generate .hpi file for manual installation
./mvnw hpi:hpi
```

## Architecture Overview

This is a Jenkins plugin that wraps **Black Duck Bridge CLI** — a binary that performs the actual security scans. The plugin handles parameter collection, Bridge CLI download/installation, and scan invocation; it does not run scans itself.

### Entry points

- **Pipeline**: `SecurityScanStep` (`extension/pipeline/`) — a `Step` implementation. Users call `security_scan(product: '...')` in Jenkinsfile.
- **Freestyle**: `SecurityScanFreestyle` (`extension/freestyle/`) — a `Builder` / `SimpleBuildStep`.
- **Global config**: `ScannerGlobalConfig` (`extension/global/`) — Jenkins global configuration page for credentials and defaults.

Both freestyle and pipeline classes implement the `SecurityScan` interface (`extension/SecurityScan.java`), which declares all scan parameters as getters.

### Execution flow

```
SecurityScanStep / SecurityScanFreestyle
  → ParameterMappingService.preparePipelineParametersMap()   // flatten UI params → Map<String,Object>
  → ParameterMappingService.getGlobalConfigurationValues()   // merge global config / env var overrides
  → ScanInitializer.initializeScanner()
      → BridgeDownloadParametersService  // resolve Bridge CLI version & install path
      → BridgeDownloadManager            // download + unzip Bridge CLI if needed
      → ScanParametersService.performScanParameterValidation()  // validate required params per product
      → SecurityScanner.runScanner()
          → ToolsParameterService.getCommandLineArgs()  // build Bridge CLI JSON input + command line
          → launcher.launch()  // exec bridge-cli binary
```

### Parameter flow

`ParameterMappingService` (43 KB) is the central translator. It reads `SecurityScan` getters and populates a `Map<String,Object>` keyed by constants from `ApplicationConstants`. This map is then serialized to JSON by `ToolsParameterService` using Jackson and passed to Bridge CLI via `--input` flag.

The `input/` package contains the Jackson-annotated POJOs that mirror Bridge CLI's JSON schema:
- `input/blackducksca/` — Black Duck SCA (formerly Blackduck)
- `input/coverity/` — Coverity Connect
- `input/polaris/` — Polaris
- `input/srm/` — Software Risk Manager
- `input/scm/{github,gitlab,bitbucket}/` — SCM PR comment parameters
- `input/network/` — SSL/proxy config

### Key classes

| Class | Purpose |
|---|---|
| `ApplicationConstants` | All string keys for the parameter map and runtime constants |
| `LoggerWrapper` | Wraps `TaskListener` — always use this instead of `System.out` |
| `ScanCredentialsHelper` | Looks up Jenkins credentials by ID |
| `Utility` | OS/arch detection, version comparison, directory separator |
| `ErrorCode` / `PluginExceptionHandler` | Typed error codes thrown as checked exceptions |

### Supported products

`SecurityProduct` enum: `BLACKDUCKSCA` (also accepts legacy `BLACKDUCK`), `COVERITY`, `POLARIS`, `SRM`.

A scan step's `product` parameter accepts one or more comma-separated product names. `ScanParametersService` splits and validates each.

### Adding a new scan parameter

1. Add constant to `ApplicationConstants`.
2. Add getter to `SecurityScan` interface.
3. Implement getter in both `SecurityScanStep` and `SecurityScanFreestyle` with `@DataBoundSetter`.
4. Add mapping in the relevant `prepare*ParametersMap` method in `ParameterMappingService`.
5. Add to the relevant `*ParametersService` under `service/scan/` for validation.
6. Add to the relevant Jackson POJO under `input/`.
7. Add help HTML files in both `extension/freestyle/SecurityScanFreestyle/` and `extension/pipeline/SecurityScanStep/` (named `help-<param_name>.html`).

### Deprecated parameters

Parameters prefixed `blackduck_*` are deprecated in favour of `blackducksca_*`. Both are still handled; deprecated ones are tracked in `ParameterMappingService.DEPRECATED_PARAMETERS` and trigger warnings.
