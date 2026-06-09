# CLAUDE.md - Black Duck Jenkins Security Plugin

This file provides comprehensive guidance to Claude Code when working with the Black Duck Jenkins security plugin. This is a Java-based Jenkins plugin that integrates Bridge CLI to provide security scanning capabilities within Jenkins workflows.

## Project Overview

### What is this Jenkins Plugin?
This Jenkins plugin provides a unified interface for running Black Duck security scans within Jenkins build environments. It leverages Bridge CLI as the underlying orchestration tool to execute various security scanning tools (Polaris, Coverity, Black Duck SCA, Software Risk Manager) and integrate results with Jenkins build artifacts and notifications.

### Key Capabilities
- **Jenkins Native Integration**: Seamless integration with Jenkins Pipeline and Freestyle jobs
- **Multi-Platform Support**: Windows, macOS, and Linux support with automatic platform detection
- **Build Integration**: Native Jenkins artifact and build status handling
- **Distributed Builds**: Support for Jenkins agent execution across different nodes
- **SCM Integration**: Support for GitHub, GitLab, and Bitbucket repository integration
- **Plugin Architecture**: Standard Jenkins HPI plugin packaging and distribution

## Architecture

### Design Patterns
- **Jenkins HPI Plugin**: Standard Jenkins plugin architecture
- **Pipeline and Freestyle**: Support for both Jenkins job types
- **Multi-Platform Integration**: Bridge CLI integration across different operating systems
- **SCM Abstraction**: Abstract SCM integration for multiple source control systems

### Key Components
- **Bridge CLI Integration**: Downloads, installs, and executes Bridge CLI
- **Jenkins API Integration**: Native Jenkins artifact and build status handling
- **SCM Services**: GitHub, GitLab, and Bitbucket integration
- **Multi-Platform Support**: Platform-specific Bridge CLI handling
- **Configuration Management**: Jenkins-native configuration and credential handling

## Development Environment

### Prerequisites
- **Java**: JDK 11+ compatibility
- **Maven**: 3.6+ for build management
- **Jenkins**: Core 2.440.3 LTS baseline for development
- **IDE**: IntelliJ IDEA or Eclipse with Maven support

### Key Dependencies
- **Jenkins Core**: 2.440.3 LTS baseline
- **Apache HttpComponents Client 5**: HTTP operations
- **SCM Integration**: GitHub, GitLab, and Bitbucket APIs
- **Pipeline API**: Jenkins workflow integration
- **JUnit Jupiter 5.6.2**: Testing framework with Mockito 2.23.4

### Development Commands
```bash
cd blackduck-security-scan-plugin

# Build plugin
mvn clean install

# Run tests
mvn test

# Package plugin
mvn package

# Generate HPI file for Jenkins installation
mvn hpi:hpi

# Run with Jenkins locally (for development)
mvn hpi:run

# Generate test coverage report
mvn jacoco:report

# Run specific test class
mvn test -Dtest=BridgeCliTest

# Debug specific functionality
mvn test -Dtest=SecurityScanStepTest -Dmaven.surefire.debug
```

## Bridge CLI Integration

### Installation and Management
The plugin automatically downloads and installs Bridge CLI from:
- **Primary**: https://repo.blackduck.com/
- **Legacy**: sig-repo.synopsys.com (deprecated)

### Configuration Parameters
- `bridgecli_install_directory` / `BRIDGECLI_INSTALL_DIRECTORY` - Installation path
- `bridgecli_download_url` / `BRIDGECLI_DOWNLOAD_URL` - Custom download URL  
- `bridgecli_download_version` / `BRIDGECLI_DOWNLOAD_VERSION` - Specific version

### Air-Gapped Environment Support
- `network_airgap` / `BRIDGE_NETWORK_AIRGAP` - Enable air-gapped mode
- Bridge CLI must be pre-installed when air-gapped mode is enabled

### Multi-Platform Support
- **Windows**: Native Windows executable support
- **macOS**: Intel and ARM architecture support
- **Linux**: x64 and ARM architecture support
- **Auto-Detection**: Automatic platform and architecture detection

## Security Tool Configuration

### Polaris (SAST/SCA)
**Required Parameters:**
- `BRIDGE_POLARIS_SERVER_URL` - Polaris server URL
- `BRIDGE_POLARIS_ACCESS_TOKEN` - Authentication token
- `BRIDGE_POLARIS_ASSESSMENT_TYPES` - Assessment types (SAST, SCA, or both)

**Optional Parameters:**
- `BRIDGE_POLARIS_APPLICATION_NAME` - Application name (defaults to job name)
- `BRIDGE_POLARIS_PROJECT_NAME` - Project name (defaults to job name)
- `BRIDGE_POLARIS_BRANCH_NAME` - Branch name for analysis

### Coverity Connect (SAST)
**Required Parameters:**
- `BRIDGE_COVERITY_URL` - Coverity server URL
- `BRIDGE_COVERITY_USER` - Username for authentication
- `BRIDGE_COVERITY_PASSPHRASE` - Password for authentication

**Optional Parameters:**
- `BRIDGE_COVERITY_PROJECT_NAME` - Project name (defaults to job name)
- `BRIDGE_COVERITY_STREAM_NAME` - Stream name for analysis
- `coverity_build_command` - Build command for compilation
- `coverity_clean_command` - Clean command before build

### Black Duck SCA
**Required Parameters:**
- `BRIDGE_BLACKDUCKSCA_URL` - Black Duck server URL
- `BRIDGE_BLACKDUCKSCA_TOKEN` - API token for authentication

**Optional Parameters:**
- `BRIDGE_BLACKDUCKSCA_SCAN_FULL` - Full scan vs rapid scan
- `BRIDGE_BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES` - Severities that fail the build
- `detect_search_depth` - Search depth in source directory

### Software Risk Manager (SRM)
**Required Parameters:**
- `BRIDGE_SRM_URL` - SRM server URL
- `BRIDGE_SRM_APIKEY` - API key for authentication
- `BRIDGE_SRM_ASSESSMENT_TYPES` - Assessment types to run

## Jenkins Integration Features

### Pipeline Integration
- **Declarative Pipeline**: Full support for declarative Jenkins Pipeline syntax
- **Scripted Pipeline**: Support for scripted Jenkins Pipeline
- **Pipeline Step**: Custom pipeline step for security scanning
- **Build Parameters**: Dynamic parameter resolution from Jenkins environment

### Freestyle Job Integration
- **Build Step**: Custom build step for Freestyle jobs
- **Post-Build Actions**: Integration with post-build processing
- **Build Environment**: Environment variable integration

### Artifact Management
- **Jenkins Artifacts**: Native Jenkins artifact archiving
- **Report Storage**: Security report storage as build artifacts
- **Log Integration**: Comprehensive logging integration with Jenkins build logs

### Build Status Integration
- **Build Result**: Integration with Jenkins build result status
- **Failure Conditions**: Configurable build failure based on security findings
- **Status Propagation**: Build status propagation based on scan results

## SCM Integration Architecture

### GitHub Integration
- **GitHub API**: Native GitHub API integration
- **GitHub Enterprise**: Support for GitHub Enterprise Server
- **Pull Requests**: PR comment integration for security findings
- **Status Checks**: GitHub status check integration

### GitLab Integration
- **GitLab API**: Native GitLab API integration
- **GitLab Enterprise**: Support for GitLab Enterprise Edition
- **Merge Requests**: MR comment integration
- **Pipeline Integration**: GitLab CI/CD integration

### Bitbucket Integration
- **Bitbucket API**: Native Bitbucket API integration
- **Bitbucket Server**: Support for Bitbucket Server (on-premises)
- **Pull Requests**: PR integration for security findings

## Testing Strategy

### Unit Testing with JUnit Jupiter
- **JUnit Jupiter 5.6.2**: Modern JUnit testing framework
- **Mockito 2.23.4**: Comprehensive mocking framework
- **JaCoCo Coverage**: 80%+ code coverage expectation
- **Parameter Validation**: Comprehensive input validation testing

### Integration Testing
- **Bridge CLI Integration**: E2E tests with actual Bridge CLI binaries included
- **Jenkins Environment**: Testing with Jenkins test harness
- **SCM Integration**: Contract tests for all supported SCM platforms
- **Multi-Platform**: Testing across different operating systems

### Test Organization
```
src/test/
├── java/io/jenkins/plugins/security/
│   ├── scan/
│   │   ├── BridgeCliTest.java
│   │   ├── SecurityScanStepTest.java
│   │   ├── ParameterValidationTest.java
│   │   └── SCMIntegrationTest.java
│   └── global/
│       └── ScannerGlobalConfigTest.java
└── resources/
    ├── demo-bridge.zip              # Test Bridge CLI binary
    └── versions.txt                 # Version compatibility data
```

## File Structure and Key Components

### Java Package Structure
```
src/main/java/io/jenkins/plugins/security/
├── scan/
│   ├── SecurityScanStep.java           # Pipeline step implementation
│   ├── SecurityScanFreestyleBuilder.java # Freestyle build step
│   ├── BridgeCliRunner.java           # Bridge CLI execution
│   ├── ParameterValidator.java        # Input parameter validation
│   ├── PlatformDetector.java          # Platform/architecture detection
│   └── service/
│       ├── SCMService.java            # SCM integration interface
│       ├── GitHubService.java         # GitHub integration
│       ├── GitLabService.java         # GitLab integration
│       └── BitbucketService.java      # Bitbucket integration
├── global/
│   └── ScannerGlobalConfig.java       # Global plugin configuration
└── model/
    ├── ScanParameters.java            # Scan parameter models
    ├── ToolConfiguration.java         # Tool-specific configuration
    └── BuildResult.java               # Build result models
```

### Jenkins Configuration Files
```
src/main/resources/
├── index.jelly                        # Plugin description
├── io/jenkins/plugins/security/
│   ├── scan/
│   │   ├── SecurityScanStep/          # Pipeline step configuration
│   │   │   ├── config.jelly
│   │   │   └── help-*.html
│   │   └── SecurityScanFreestyleBuilder/ # Freestyle configuration
│   │       ├── config.jelly
│   │       └── help-*.html
│   └── global/
│       └── ScannerGlobalConfig/       # Global configuration
│           └── config.jelly
└── webapp/
    ├── icons/blackduck.png            # Plugin icons
    ├── scripts/                       # JavaScript files
    └── styles/                        # CSS files
```

### Key Java Classes
```java
// Bridge CLI execution and management
public class BridgeCliRunner {
    public ExecutionResult runScan(ScanParameters params)
    public String downloadBridgeCli(String version)
    public void validateInstallation(String installPath)
}

// Parameter validation and processing
public class ParameterValidator {
    public ValidationResult validateParameters(ScanParameters params)
    public boolean isToolConfigured(ToolType tool, ScanParameters params)
}

// SCM integration interface
public interface SCMService {
    void createPullRequestComment(String repoUrl, int prNumber, String comment)
    void updateBuildStatus(String repoUrl, String commitSha, BuildStatus status)
}

// Jenkins Pipeline step
@Extension
public class SecurityScanStep extends Step {
    public StepExecution start(StepContext context)
}
```

## Performance Optimization

### Caching Strategy
- **Bridge CLI Caching**: Jenkins tool installation caching
- **HTTP Client Connection Pooling**: Reuse HTTP connections for SCM APIs
- **Configuration Caching**: Cache validated configurations across builds
- **Multi-Node Efficiency**: Efficient artifact transfer across Jenkins agents

### Memory Management
- **Resource Cleanup**: Proper cleanup of temporary files and processes
- **Stream Processing**: Efficient handling of large scan outputs
- **Agent Memory**: Optimized memory usage on Jenkins agents

## Security Best Practices

### Credential Management
- **Jenkins Credentials**: Integration with Jenkins credential management system
- **Secret Masking**: Automatic masking of sensitive information in build logs
- **Credential Binding**: Secure credential binding for build steps
- **Scope Management**: Proper credential scope management

### SSL Security
- **Certificate Validation**: Proper SSL certificate validation for all HTTP connections
- **Custom CA Support**: Support for custom certificate authorities
- **Trust Store Management**: Secure certificate trust store handling

## Plugin Configuration and Management

### Global Configuration
- **Jenkins Global Config**: System-wide plugin configuration
- **Default Parameters**: System-level default parameter values
- **Tool Installations**: Global Bridge CLI installation management

### Job-Level Configuration
- **Pipeline Configuration**: Declarative and scripted pipeline configuration
- **Freestyle Configuration**: GUI-based configuration for freestyle jobs
- **Environment Variables**: Dynamic environment variable resolution

### Security Configuration
- **Permission Management**: Jenkins-native permission system integration
- **Role-Based Access**: Role-based access control integration
- **Audit Logging**: Integration with Jenkins audit logging

## Debugging and Diagnostics

### Debug Output
- **Build Console Logs**: Comprehensive logging to Jenkins build console
- **Debug Mode**: Enhanced debug logging when enabled
- **Bridge CLI Logs**: Bridge CLI execution logs and output
- **SCM API Logs**: SCM API interaction logging

### Diagnostic Collection
- **System Information**: Jenkins environment and system details
- **Plugin Information**: Plugin version and configuration details
- **Build Environment**: Complete build environment capture
- **Error Context**: Comprehensive error context and stack traces

## Common Development Tasks

### Adding New Security Tool Support
1. Update `ToolConfiguration.java` with new tool parameters
2. Add validation logic in `ParameterValidator.java`
3. Update Bridge CLI parameter generation
4. Add comprehensive unit tests
5. Update Jelly configuration files for UI

### Extending SCM Integration
1. Create new service class implementing `SCMService`
2. Add SCM-specific API integration
3. Update parameter validation for new SCM
4. Add comprehensive testing for new SCM integration

### Jenkins Version Updates
1. Update Jenkins baseline version in `pom.xml`
2. Test compatibility with new Jenkins APIs
3. Update deprecated API usage
4. Validate plugin packaging and distribution

### UI Configuration Updates
1. Update Jelly configuration files
2. Add/modify JavaScript for dynamic UI behavior
3. Update CSS for styling
4. Test UI across different Jenkins versions

## Troubleshooting Guide

### Common Issues and Solutions

#### Plugin Installation Issues
- Verify Jenkins version compatibility (2.440.3 LTS baseline)
- Check Java version compatibility (JDK 11+)
- Validate plugin dependencies are available
- Review Jenkins plugin manager logs

#### Bridge CLI Download Failures
- Check network connectivity from Jenkins agents
- Verify `bridgecli_download_url` parameter if using custom URL
- Check proxy configuration on Jenkins agents
- Validate SSL certificates on Jenkins system

#### Build Agent Issues
- Verify Bridge CLI can execute on target agent
- Check agent platform and architecture compatibility
- Validate agent permissions for file system access
- Review agent workspace cleanup policies

#### SCM Integration Issues
- Verify SCM credentials are properly configured
- Check SCM API endpoints and authentication
- Validate webhook and API rate limiting
- Review SCM permission requirements

### Debug Information Collection
When reporting issues, collect:
- Jenkins build console logs with debug enabled
- Jenkins system logs (`$JENKINS_HOME/logs/`)
- Plugin configuration export
- Bridge CLI execution logs
- SCM API response details
- Jenkins agent system information

## Deployment and Distribution

### Plugin Packaging
- **HPI Generation**: Maven HPI plugin generates `.hpi` files
- **Dependency Management**: Maven dependency resolution and packaging
- **Metadata**: Plugin metadata and Jenkins compatibility information

### Jenkins Plugin Center
- **Plugin Distribution**: Official Jenkins Plugin Center distribution
- **Version Management**: Semantic versioning and release management
- **Compatibility Matrix**: Jenkins version compatibility tracking

### Enterprise Deployment
- **Custom Plugin Distribution**: Enterprise plugin repository support
- **Configuration Management**: Centralized configuration management
- **Update Management**: Controlled plugin update processes

## Future Development Considerations

### Architecture Evolution
- Maintain Jenkins HPI plugin architecture standards
- Keep SCM integration modular and extensible
- Preserve multi-platform Bridge CLI support
- Maintain high test coverage (80%+)

### New Feature Integration
- Follow Jenkins plugin development best practices
- Add comprehensive unit and integration tests
- Update parameter validation and UI configuration
- Maintain backward compatibility with existing jobs

### Maintenance Strategy
- Regular dependency updates with security scanning
- Monitor Jenkins core API changes and deprecations
- Update Bridge CLI compatibility as new versions are released
- Maintain plugin center distribution and documentation
- Update SCM API integrations as platforms evolve

This Jenkins plugin provides a robust, enterprise-grade foundation for Black Duck security scanning within Jenkins environments, supporting both Pipeline and Freestyle jobs with comprehensive SCM integration, multi-platform support, and Jenkins-native artifact and build status handling.