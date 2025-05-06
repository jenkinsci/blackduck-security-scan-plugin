package io.jenkins.plugins.security.scan.global;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.model.TopLevelItem;
import io.jenkins.plugins.security.scan.action.SarifReport;
import io.jenkins.plugins.security.scan.action.SecurityIssue;
import io.jenkins.plugins.security.scan.global.enums.BuildStatus;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;

public class Utility {

    public static String getDirectorySeparator(FilePath workspace, TaskListener listener) {
        String os = getAgentOs(workspace, listener);

        if (os != null && os.contains("win")) {
            return "\\";
        } else {
            return "/";
        }
    }

    public static String getAgentOs(FilePath workspace, TaskListener listener) {
        String os = null;
        LoggerWrapper logger = new LoggerWrapper(listener);

        if (workspace.isRemote()) {
            try {
                os = workspace.act(new OsNameTask());
            } catch (IOException | InterruptedException e) {
                logger.error(ApplicationConstants.FETCHING_OS_INFORMATION_FOR_THE_AGENT_NODE_EXCEPTION, e.getMessage());
                Thread.currentThread().interrupt();
            }
        } else {
            os = System.getProperty("os.name").toLowerCase();
        }

        return os;
    }

    public static String getAgentOsArch(FilePath workspace, TaskListener listener) {
        String arch = null;
        LoggerWrapper logger = new LoggerWrapper(listener);

        if (workspace.isRemote()) {
            try {
                arch = workspace.act(new OsArchTask());
            } catch (IOException | InterruptedException e) {
                logger.error(
                        ApplicationConstants.FETCHING_OS_ARCHITECTURE_INFORMATION_FOR_THE_AGENT_NODE_EXCEPTION,
                        e.getMessage());
                Thread.currentThread().interrupt();
            }
        } else {
            arch = System.getProperty("os.arch").toLowerCase();
        }

        return arch;
    }

    public static void removeFile(String filePath, FilePath workspace, TaskListener listener) {
        LoggerWrapper logger = new LoggerWrapper(listener);
        try {
            FilePath file = new FilePath(workspace.getChannel(), filePath);
            file = file.absolutize();

            if (file.exists()) {
                file.delete();
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.DELETING_FILE_EXCEPTION, e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    public static boolean isStringNullOrBlank(String str) {
        return str == null || str.isBlank() || str.equals("null");
    }

    public static HttpURLConnection getHttpURLConnection(URL url, EnvVars envVars, LoggerWrapper logger) {
        try {
            String proxy = getProxy(url, envVars, logger);
            if (proxy.equals(ApplicationConstants.NO_PROXY)) {
                return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            } else {
                URL proxyURL = new URL(proxy);

                HttpURLConnection connection = (HttpURLConnection) url.openConnection(
                        new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyURL.getHost(), proxyURL.getPort())));
                setDefaultProxyAuthenticator(proxyURL.getUserInfo());

                return connection;
            }
        } catch (IOException e) {
            logger.error(ApplicationConstants.HTTP_URL_CONNECTION_EXCEPTION, e.getMessage());
        }

        return null;
    }

    public static String getProxy(URL url, EnvVars envVars, LoggerWrapper logger) throws IOException {
        String noProxy = getEnvOrSystemProxyDetails(ApplicationConstants.NO_PROXY, envVars);
        if (!isStringNullOrBlank(noProxy)) {
            logger.info("Found NO_PROXY configuration - " + noProxy);
            String[] noProxies = noProxy.split(",");

            for (String noProxyHost : noProxies) {
                if (noProxyHost.startsWith("*") && noProxyHost.length() == 1) {
                    return ApplicationConstants.NO_PROXY;
                } else if (noProxyHost.startsWith("*") && noProxyHost.length() > 2) {
                    noProxyHost = noProxyHost.substring(2);
                    if (url.toString().contains(noProxyHost)) {
                        return ApplicationConstants.NO_PROXY;
                    }
                }
            }
        }

        return getProxyValue(envVars, logger);
    }

    public static String getProxyValue(EnvVars envVars, LoggerWrapper logger) throws MalformedURLException {
        String httpsProxy = getEnvOrSystemProxyDetails(ApplicationConstants.HTTPS_PROXY, envVars);
        if (!isStringNullOrBlank(httpsProxy)) {
            logger.info("Found HTTPS_PROXY configuration - " + getMaskedProxyUrl(httpsProxy));
            return httpsProxy;
        }

        String httpProxy = getEnvOrSystemProxyDetails(ApplicationConstants.HTTP_PROXY, envVars);
        if (!isStringNullOrBlank(httpProxy)) {
            logger.info("Found HTTP_PROXY configuration - " + getMaskedProxyUrl(httpProxy));
            return httpProxy;
        }

        return ApplicationConstants.NO_PROXY;
    }

    public static String getEnvOrSystemProxyDetails(String proxyType, EnvVars envVars) {
        String proxyDetails = envVars.get(proxyType);
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = envVars.get(proxyType.toLowerCase());
        }
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = System.getenv(proxyType);
        }
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = System.getenv(proxyType.toLowerCase());
        }

        return proxyDetails;
    }

    public static void setDefaultProxyAuthenticator(String userInfo) {
        if (!isStringNullOrBlank(userInfo)) {
            String[] userInfoArray = userInfo.split(":");
            if (userInfoArray.length == 2) {
                Authenticator.setDefault(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(userInfoArray[0], userInfoArray[1].toCharArray());
                    }
                });
            }
        }
    }

    private static String getMaskedProxyUrl(String proxyUrlString) throws MalformedURLException {
        URL proxyUrl = new URL(proxyUrlString);
        String userInfo = proxyUrl.getUserInfo();
        if (!isStringNullOrBlank(userInfo) && userInfo.split(":").length > 1) {
            return proxyUrlString.replace(userInfo.split(":")[1], "*****");
        }

        return proxyUrlString;
    }

    public static Map<String, Boolean> installedBranchSourceDependencies() {
        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        Jenkins jenkins = Jenkins.getInstanceOrNull();

        if (jenkins != null) {
            if (jenkins.getPlugin(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME) != null) {
                installedBranchSourceDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);
            }
            if (jenkins.getPlugin(ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME) != null) {
                installedBranchSourceDependencies.put(ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, true);
            }
            if (jenkins.getPlugin(ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME) != null) {
                installedBranchSourceDependencies.put(ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, true);
            }
        }

        return installedBranchSourceDependencies;
    }

    public static String jenkinsJobType(EnvVars envVars) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();

        String jobName = envVars.get(ApplicationConstants.ENV_JOB_NAME_KEY);

        // Extract the part before the last '/' for potential multibranch projects
        if (jobName != null) {
            String jobNameForMultibranchProject =
                    jobName.contains("/") ? jobName.substring(0, jobName.lastIndexOf('/')) : jobName;

            // If item is not a 'Folder', then it is a Multibranch pipeline job
            TopLevelItem item = jenkins != null
                    ? jenkins.getItemByFullName(jobNameForMultibranchProject, TopLevelItem.class)
                    : null;

            // If 'item' is an instanceof 'Folder', it is either 'WorkflowJob' or 'FreestyleJob'
            // Then try to get the item type with actual 'jobName'
            if (item instanceof Folder && jenkins != null) {
                TopLevelItem actualItem = jenkins.getItemByFullName(jobName, TopLevelItem.class);
                if (actualItem != null) {
                    item = actualItem;
                }
            }

            if (item != null) {
                return item.getClass().getSimpleName();
            }
        }
        return "UnknownJobType";
    }

    public static String getDefaultSarifReportFilePath(boolean isBlackDuckScan, boolean isPolarisDuckScan) {
        return isBlackDuckScan
                ? ApplicationConstants.DEFAULT_BLACKDUCKSCA_SARIF_REPORT_FILE_PATH.concat(
                        ApplicationConstants.SARIF_REPORT_FILENAME)
                : isPolarisDuckScan
                        ? ApplicationConstants.DEFAULT_POLARIS_SARIF_REPORT_FILE_PATH.concat(
                                ApplicationConstants.SARIF_REPORT_FILENAME)
                        : "";
    }

    public static String getCustomSarifReportFilePath(
            Map<String, Object> scanParams, boolean isBlackDuckScan, boolean isPolarisDuckScan) {
        return isBlackDuckScan
                ? (String) scanParams.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY)
                : isPolarisDuckScan
                        ? (String) scanParams.get(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY)
                        : "";
    }

    public static String determineSARIFReportFilePath(
            String customSarifReportFilePath, String defaultSarifReportFilePath) {
        return customSarifReportFilePath != null ? customSarifReportFilePath : defaultSarifReportFilePath;
    }

    public static String determineSARIFReportFileName(String customSarifReportFilePath) {
        return customSarifReportFilePath != null
                ? new File(customSarifReportFilePath).getName()
                : ApplicationConstants.SARIF_REPORT_FILENAME;
    }

    public static boolean isPullRequestEvent(EnvVars envVars) {
        return envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null;
    }

    public static Result getMappedResultForBuildStatus(BuildStatus buildStatus) {
        if (buildStatus.equals(BuildStatus.FAILURE)) {
            return Result.FAILURE;
        }
        if (buildStatus.equals(BuildStatus.UNSTABLE)) {
            return Result.UNSTABLE;
        }
        if (buildStatus.equals(BuildStatus.SUCCESS)) {
            return Result.SUCCESS;
        }
        return null;
    }

    public static String extractVersionFromUrl(String url) {
        String regex = "/(\\d+\\.\\d+\\.\\d+)/";
        Pattern pattern = Pattern.compile(regex);
        String version;

        Matcher matcher = pattern.matcher(url);

        if (matcher.find()) {
            version = matcher.group(1);
        } else {
            version = ApplicationConstants.NOT_AVAILABLE;
        }

        return version;
    }

    public static JsonNode parseJsonFile(String jsonString) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.readTree(jsonString);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static List<SecurityIssue> parseSarifReport(FilePath workspace, String reportPath)
            throws IOException, InterruptedException {
        FilePath reportFile = workspace.child(reportPath);
        if (!reportFile.exists()) {
            return Collections.emptyList();
        }

        ObjectMapper mapper = new ObjectMapper();
        SarifReport report = mapper.readValue(reportFile.read(), SarifReport.class);

        List<SecurityIssue> issues = new ArrayList<>();

        for (SarifReport.Run run : report.getRuns()) {
            String toolName = run.getTool().getDriver().getName();

            // Map for rule definitions that contain severity ratings
            Map<String, String> ruleSeverityMap = new HashMap<>();
            Map<String, String> ruleHelpMap = new HashMap<>();
            Map<String, String> ruleShortDescMap = new HashMap<>();

            if (run.getTool().getDriver().getRules() != null) {
                for (SarifReport.Rule rule : run.getTool().getDriver().getRules()) {
                    // Map severity
                    if (rule.getProperties() != null && rule.getProperties().getSecuritySeverity() != null) {
                        String severity =
                                mapSecuritySeverityRating(rule.getProperties().getSecuritySeverity());
                        ruleSeverityMap.put(rule.getId(), severity);
                    }
                    // Map help content
                    if (rule.getHelp() != null && rule.getHelp().getMarkdown() != null) {
                        ruleHelpMap.put(rule.getId(), rule.getHelp().getMarkdown());
                    }
                    // Map short description
                    if (rule.getShortDescription() != null
                            && rule.getShortDescription().getText() != null) {
                        ruleShortDescMap.put(
                                rule.getId(), rule.getShortDescription().getText());
                    }
                }
            }

            for (SarifReport.Result result : run.getResults()) {
                // Use the mapped severity if available, otherwise use the level
                String severity = ruleSeverityMap.getOrDefault(
                        result.getRuleId(),
                        result.getLevel() != null ? mapLevelToSeverity(result.getLevel()) : "Unknown");
                String helpMarkdown = ruleHelpMap.getOrDefault(result.getRuleId(), "");
                String shortDesc = ruleShortDescMap.getOrDefault(result.getRuleId(), ""); // Get short description

                for (SarifReport.Location location : result.getLocations()) {
                    SarifReport.PhysicalLocation physicalLocation = location.getPhysicalLocation();
                    String filePath = physicalLocation.getArtifactLocation().getUri();
                    int line = physicalLocation.getRegion().getStartLine();

                    // Load code snippet
                    List<String> codeSnippet = new ArrayList<>();
                    int contextLines = 3; // You can make this configurable
                    int startLineNumber = Math.max(1, line - contextLines);
                    int highlightedLineIndex = line - startLineNumber;

                    try {
                        FilePath sourceFile = workspace.child(filePath);
                        if (sourceFile.exists()) {
                            try (BufferedReader reader = new BufferedReader(
                                    new InputStreamReader(sourceFile.read(), StandardCharsets.UTF_8))) {

                                // Skip lines before our context
                                for (int i = 1; i < startLineNumber; i++) {
                                    reader.readLine();
                                }

                                // Read the lines we want to display
                                int endLine = line + contextLines;
                                String codeLine;
                                int currentLine = startLineNumber;

                                while ((codeLine = reader.readLine()) != null && currentLine <= endLine) {
                                    codeSnippet.add(codeLine);
                                    currentLine++;
                                }
                            }
                        }
                    } catch (Exception e) {
                        // If we can't read the file, use a placeholder
                        codeSnippet = Collections.singletonList("// Could not read source file: " + e.getMessage());
                    }

                    issues.add(new SecurityIssue(
                            result.getRuleId(),
                            result.getMessage().getText(),
                            filePath,
                            line,
                            severity,
                            toolName,
                            helpMarkdown,
                            shortDesc,
                            codeSnippet,
                            startLineNumber,
                            highlightedLineIndex));
                }
            }
        }

        return issues;
    }

    private static String mapSecuritySeverityRating(String securitySeverity) {
        try {
            double value = Double.parseDouble(securitySeverity);
            if (value >= 9.0) return "Critical";
            if (value >= 7.0) return "High";
            if (value >= 4.0) return "Medium";
            if (value >= 0.1) return "Low";
            return "None";
        } catch (NumberFormatException e) {
            return "Unknown";
        }
    }

    private static String mapLevelToSeverity(String level) {
        if (level == null) return "Unknown";
        switch (level.toLowerCase()) {
            case "error":
                return "High";
            case "warning":
                return "Medium";
            case "note":
                return "Low";
            case "none":
                return "None";
            default:
                return "Unknown";
        }
    }

    public static boolean isBoolean(String value) {
        return value.equals("true") || value.equals("false");
    }
}
