# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Black Duck Security Scan Jenkins Plugin

This is a Jenkins plugin that integrates Black Duck security scanning tools (Polaris, Coverity, Black Duck SCA, Software Risk Manager) via Bridge CLI. The plugin supports both Pipeline and Freestyle job types.

## Development Commands

### Build and Test
```bash
# Build the project
./mvnw clean install

# Run tests with coverage
./mvnw test

# Generate HPI file for Jenkins installation
./mvnw hpi:hpi

# Run Jenkins locally with plugin deployed
./mvnw hpi:run
```

### Testing Individual Components
```bash
# Run specific test
./mvnw test -Dtest=SecurityScanFreestyleTest

# Run tests for specific package
./mvnw test -Dtest="io.jenkins.plugins.security.scan.service.**"
```

### Docker Development Environment
```bash
# Build project first
./mvnw clean install && ./mvnw hpi:hpi

# Run Jenkins in Docker
docker-compose up
```

## Architecture Overview

### Core Architecture Patterns

1. **Bridge CLI Integration**: The plugin acts as a wrapper around Bridge CLI, which orchestrates multiple Black Duck security tools
2. **Multi-Tool Support**: Supports Polaris (SAST/SCA), Coverity (SAST), Black Duck SCA, and Software Risk Manager (SRM)
3. **Parameter Mapping**: Complex parameter validation and mapping system that handles tool-specific configurations
4. **SCM Integration**: Native support for GitHub, GitLab, and Bitbucket repository detection and PR commenting

### Key Components

#### Core Execution Flow
- `SecurityScanner.java` - Main execution orchestrator that runs Bridge CLI
- `ScanInitializer.java` - Handles plugin initialization and Bridge CLI setup
- `BridgeDownloadManager.java` / `BridgeInstall.java` - Manages Bridge CLI download and installation

#### Extension Points
- `SecurityScanStep.java` - Pipeline step implementation with extensive parameter support
- `SecurityScanFreestyle.java` - Freestyle job configuration
- `ScannerGlobalConfig.java` - Global plugin configuration

#### Service Layer
- `ParameterMappingService.java` - Maps UI parameters to Bridge CLI arguments
- `ToolsParameterService.java` - Generates command line arguments for Bridge CLI
- Tool-specific parameter services in `service/scan/` for each security product
- SCM services in `service/scm/` for repository operations

#### Input Models
The `input/` package contains POJOs that mirror Bridge CLI's JSON input structure:
- Security tool configurations (blackducksca/, coverity/, polaris/, srm/)
- SCM configurations (github/, gitlab/, bitbucket/)
- Network and project configurations

### Plugin Architecture Patterns

1. **Dual Job Support**: Both Pipeline (`SecurityScanStep`) and Freestyle (`SecurityScanFreestyle`) implementations
2. **Parameter Inheritance**: Complex inheritance chain through multiple interfaces (SecurityScan, PrCommentScan, FixPrScan, etc.)
3. **Transient Credentials**: Sensitive fields marked as `transient` to prevent serialization
4. **Jelly UI Configuration**: Extensive Jelly templates for dynamic UI based on selected security product

### SCM Integration

The plugin automatically detects SCM context from Jenkins job configuration:
- `GithubRepositoryService.java` - GitHub integration with PR comments and fix PRs
- `GitlabRepositoryService.java` - GitLab merge request integration  
- `BitbucketRepositoryService.java` - Bitbucket pull request integration

### Error Handling

- `PluginExceptionHandler.java` - Custom exception handling with error codes
- `ErrorCode.java` - Centralized error code definitions
- `LoggerWrapper.java` - Standardized logging with different levels

## Key Configuration Areas

### Security Product Selection
The plugin uses a product selection mechanism where users choose from:
- POLARIS (combined SAST/SCA)
- COVERITY (SAST only)
- BLACKDUCKSCA (SCA only) 
- SRM (Software Risk Manager)

### Parameter Validation
- Tool-specific parameter validation only occurs when that tool is selected
- Complex validation rules in `ParameterMappingService`
- Support for deprecated parameter names with warnings

### Bridge CLI Management
- Automatic download from configurable URLs (defaults to repo.blackduck.com)
- Version-specific installation with backward compatibility
- Air-gap mode support for disconnected environments

## Testing Strategy

### Test Coverage
- JUnit Jupiter 5.6.2 with Mockito 2.23.4 for mocking
- JaCoCo integration with 80%+ coverage expectation
- Comprehensive parameter validation testing

### Test Categories
- Unit tests for service classes and utilities
- Integration tests with actual Bridge CLI binaries (included in test resources)
- SCM integration testing for all supported platforms
- Parameter mapping and validation testing

### Running Tests
The plugin includes realistic test scenarios:
- Bridge CLI binaries in `src/test/resources/demo-bridge.zip`
- Mock SCM environments for testing repository detection
- Comprehensive parameter validation test cases

## Security and Credentials

### Credential Management
- Integration with Jenkins credential system
- Support for various credential types (username/password, tokens, etc.)
- Transient field handling for sensitive data
- Credential masking in logs

### Global Configuration
Global settings are managed through `ScannerGlobalConfig`:
- Security tool server URLs and credentials
- Bridge CLI download configuration
- Network settings (SSL, proxy, air-gap mode)
- SCM integration credentials

## UI and User Experience

### Dynamic UI
- JavaScript-driven UI that shows/hides sections based on product selection
- Progressive disclosure of advanced options
- Validation feedback and help text
- Consistent styling across Pipeline and Freestyle configurations

### Jelly Templates
Extensive Jelly template system in `src/main/resources/`:
- Product-specific configuration sections
- Help files for each parameter
- Localization support structure

## Build and Release Process

### Maven Configuration
- Jenkins plugin parent POM with baseline Jenkins 2.440.3
- JaCoCo code coverage integration
- Apache HttpComponents Client 5 for HTTP operations
- SCM plugin dependencies for repository integration

### CI/CD Integration
- GitHub Actions workflow for CI/CD
- Jenkins infrastructure for plugin development
- Spotless code formatting integration
- Automated testing on multiple platforms (Linux/Windows, Java 11/17)

## Common Development Tasks

### Adding New Security Tool Support
1. Create input model POJOs in `input/[tool-name]/`
2. Implement parameter service in `service/scan/[tool-name]/`
3. Add tool-specific validation in `ParameterMappingService`
4. Update UI templates with new tool sections
5. Add comprehensive test coverage

### Extending SCM Integration
1. Implement new service in `service/scm/[platform]/`
2. Add SCM detection logic in `SCMRepositoryService`
3. Update parameter mapping for platform-specific features
4. Add integration tests

### Parameter Management
- All parameters follow naming convention: `[tool]_[category]_[parameter]`
- Deprecation support through parameter mapping service
- Validation occurs in service layer, not in UI models
- Environment variable support for all parameters

This plugin demonstrates enterprise-grade Jenkins plugin development with comprehensive security tool integration, extensive testing, and robust error handling.