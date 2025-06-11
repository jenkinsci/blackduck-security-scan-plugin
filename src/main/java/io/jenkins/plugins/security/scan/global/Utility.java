package io.jenkins.plugins.security.scan.global;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.model.TopLevelItem;
import io.jenkins.plugins.security.scan.global.enums.BuildStatus;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
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

    public static String getCustomSarifReportFilePath(
            Map<String, Object> scanParams, boolean isBlackDuckScan, boolean isPolarisScan) {
        return isBlackDuckScan
                ? (String) scanParams.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY)
                : isPolarisScan
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

    public static boolean isBoolean(String value) {
        return value.equals("true") || value.equals("false");
    }

    public static String getSarifReportFilePathFromScanInfo(
            JsonNode rootNode, boolean isBlackDuckScan, boolean isPolarisScan) {
        if (rootNode == null) {
            return null;
        }

        if (isBlackDuckScan
                && rootNode.has(ApplicationConstants.BLACKDUCKSCA_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY)) {
            return rootNode.get(ApplicationConstants.BLACKDUCKSCA_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY)
                    .asText();
        }
        if (isPolarisScan
                && rootNode.has(ApplicationConstants.POLARIS_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY)) {
            return rootNode.get(ApplicationConstants.POLARIS_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY)
                    .asText();
        }
        return null;
    }

    public static String resolveSarifReportFilePath(
            Map<String, Object> scanParams,
            FilePath workspace,
            boolean isBlackDuckScan,
            boolean isPolarisScan,
            LoggerWrapper logger) {
        // Custom path
        String customPath = getCustomSarifReportFilePath(scanParams, isBlackDuckScan, isPolarisScan);
        if (!isStringNullOrBlank(customPath)) {
            return customPath;
        }

        // scan_info_out.json
        try {
            FilePath filePath = workspace.child(ApplicationConstants.SCAN_INFO_OUT_FILE_NAME);
            if (filePath.exists()) {
                JsonNode rootNode = parseJsonFile(filePath.readToString());
                String scanInfoPath = getSarifReportFilePathFromScanInfo(rootNode, isBlackDuckScan, isPolarisScan);
                if (!isStringNullOrBlank(scanInfoPath)) {
                    return scanInfoPath;
                }
            }
        } catch (Exception e) {
            logger.info(ApplicationConstants.EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE, e.getMessage());
        }

        // Legacy path
        return isBlackDuckScan
                ? ApplicationConstants.DEFAULT_BLACKDUCKSCA_SARIF_REPORT_LEGACY_FILE_PATH
                        + ApplicationConstants.SARIF_REPORT_FILENAME
                : isPolarisScan
                        ? ApplicationConstants.DEFAULT_POLARIS_SARIF_REPORT_LEGACY_FILE_PATH
                                + ApplicationConstants.SARIF_REPORT_FILENAME
                        : "";
    }
}
