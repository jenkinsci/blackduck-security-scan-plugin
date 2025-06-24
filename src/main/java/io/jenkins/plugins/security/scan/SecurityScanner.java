package io.jenkins.plugins.security.scan;

import com.fasterxml.jackson.databind.JsonNode;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.security.scan.action.IssueAction;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.IssueCalculator;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.ReportType;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.ParameterMappingService;
import io.jenkins.plugins.security.scan.service.ToolsParameterService;
import io.jenkins.plugins.security.scan.service.diagnostics.UploadReportService;
import io.jenkins.plugins.security.scan.service.scan.ScanParametersService;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class SecurityScanner {
    private final Run<?, ?> run;
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final Launcher launcher;
    private final FilePath workspace;
    private final EnvVars envVars;
    private final ToolsParameterService toolsParameterService;

    public SecurityScanner(
            Run<?, ?> run, TaskListener listener, Launcher launcher, FilePath workspace, EnvVars envVars) {
        this.run = run;
        this.listener = listener;
        this.launcher = launcher;
        this.workspace = workspace;
        this.envVars = envVars;
        this.toolsParameterService = new ToolsParameterService(listener, envVars, workspace);
        this.logger = new LoggerWrapper(listener);
    }

    public int runScanner(Map<String, Object> scanParams, FilePath bridgeInstallationPath)
            throws PluginExceptionHandler {
        int scanner = 0;

        List<String> commandLineArgs = toolsParameterService.getCommandLineArgs(scanParams, bridgeInstallationPath);

        logger.info("Executable command line arguments: "
                + commandLineArgs.stream()
                        .map(arg -> arg.concat(" "))
                        .collect(Collectors.joining())
                        .trim());

        try {
            logger.println();
            logger.println(
                    "******************************* %s *******************************",
                    "START EXECUTION OF BRIDGE CLI");

            scanner = launcher.launch()
                    .cmds(commandLineArgs)
                    .envs(envVars)
                    .pwd(workspace)
                    .stdout(listener)
                    .quiet(true)
                    .join();
        } catch (Exception e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_INVOKING_BRIDGE_CLI, e.getMessage());
            Thread.currentThread().interrupt();
        } finally {
            logger.println(
                    "******************************* %s *******************************",
                    "END EXECUTION OF BRIDGE CLI");

            toolsParameterService.removeTemporaryInputJson(commandLineArgs);

            handleDiagnostics(scanParams);
            handleSarifReports(scanParams);

            handleIssueCount(scanParams);
        }

        return scanner;
    }

    public void handleDiagnostics(Map<String, Object> scanParams) {
        if (Objects.equals(scanParams.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY), true)) {
            UploadReportService uploadReportService = new UploadReportService(
                    run,
                    listener,
                    launcher,
                    envVars,
                    new ArtifactArchiver(ApplicationConstants.ALL_FILES_WILDCARD_SYMBOL));
            uploadReportService.archiveReports(
                    workspace.child(ApplicationConstants.BRIDGE_REPORT_DIRECTORY), ReportType.DIAGNOSTIC);
        }
    }

    public void handleSarifReports(Map<String, Object> scanParams) {
        boolean createBlackDuckSarif =
                Objects.equals(scanParams.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY), true);
        boolean createPolarisSarif =
                Objects.equals(scanParams.get(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY), true);
        if (!createBlackDuckSarif && !createPolarisSarif) {
            return;
        }

        String changeId = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        boolean isPullRequest = changeId != null;
        logger.info((isPullRequest ? "This is a (PR/MR) event" : "This is not a (PR/MR) event")
                + (isPullRequest ? " (PR/MR Number: " + changeId + ")" : ""));

        ScanParametersService scanParametersService = new ScanParametersService(listener);
        Set<String> scanType = scanParametersService.getSecurityProducts(scanParams);
        boolean isBlackDuckScan = scanType.contains(SecurityProduct.BLACKDUCK.name())
                || scanType.contains(SecurityProduct.BLACKDUCKSCA.name());
        boolean isPolarisScan = scanType.contains(SecurityProduct.POLARIS.name());

        boolean waitForScan = true;
        if (isBlackDuckScan && scanParams.containsKey(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY)) {
            waitForScan = (Boolean) scanParams.get(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY);
        } else if (isPolarisScan && scanParams.containsKey(ApplicationConstants.POLARIS_WAITFORSCAN_KEY)) {
            waitForScan = (Boolean) scanParams.get(ApplicationConstants.POLARIS_WAITFORSCAN_KEY);
        }

        if (isPullRequest || !waitForScan) {
            return;
        }

        String reportFilePath =
                Utility.resolveSarifReportFilePath(scanParams, workspace, isBlackDuckScan, isPolarisScan, logger);
        String reportFileName = Utility.determineSARIFReportFileName(reportFilePath);

        UploadReportService uploadReportService =
                new UploadReportService(run, listener, launcher, envVars, new ArtifactArchiver(reportFileName));
        uploadReportService.archiveReports(workspace.child(reportFilePath), ReportType.SARIF);
    }

    public void handleIssueCount(Map<String, Object> scanParams) {
        try {
            FilePath filePath = workspace.child(ApplicationConstants.SCAN_INFO_OUT_FILE_NAME);
            if (!filePath.exists()) {
                logger.info(ApplicationConstants.SCAN_INFO_FILE_NOT_FOUND);
                return;
            }

            logger.info("Retrieving the issue count from the scan results");

            String product = scanParams.get(ApplicationConstants.PRODUCT_KEY).toString();
            String productUrl = ParameterMappingService.getProductUrl(scanParams);
            JsonNode rootNode = Utility.parseJsonFile(filePath.readToString());

            IssueCalculator issueCalculator = new IssueCalculator();
            String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product.toLowerCase());
            int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product.toLowerCase());

            boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
            if (totalIssues != -1 && !isPullRequestEvent) {
                logger.info("Total issues found: " + totalIssues);
                run.addAction(new IssueAction(
                        product.toLowerCase(),
                        totalIssues,
                        Utility.isStringNullOrBlank(issuesUrl) ? productUrl : issuesUrl));
            } else {
                logger.info(ApplicationConstants.SCAN_INFO_ISSUE_COUNT_NOT_FOUND);
            }
        } catch (IOException | InterruptedException | RuntimeException e) {
            logger.info(ApplicationConstants.EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE, e.getMessage());
            Thread.currentThread().interrupt();
        }
    }
}
