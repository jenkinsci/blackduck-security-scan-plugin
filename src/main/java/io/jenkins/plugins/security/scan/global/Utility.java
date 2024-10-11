package io.jenkins.plugins.security.scan.global;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.ProxyConfiguration;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.model.TopLevelItem;
import io.jenkins.plugins.security.scan.global.enums.BuildStatus;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
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

    public static HttpURLConnection getHttpURLConnection(URL url, LoggerWrapper logger) {
        try {
            ProxyConfiguration proxyConfig = Jenkins.get().proxy;
            if (proxyConfig == null) {
                return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            }

            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyConfig.name, proxyConfig.port));
            HttpURLConnection connection = (HttpURLConnection) url.openConnection(proxy);

            if (proxyConfig.getUserName() != null) {
                setDefaultProxyAuthenticator(proxyConfig.getUserName(), proxyConfig.getPassword());
            }

            return connection;
        } catch (IOException e) {
            logger.error(ApplicationConstants.HTTP_URL_CONNECTION_EXCEPTION, e.getMessage());
        }

        return null;
    }

    public static void setDefaultProxyAuthenticator(String userName, String password) {
        if (!isStringNullOrBlank(userName) && !isStringNullOrBlank(password)) {
            Authenticator.setDefault(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(userName, password.toCharArray());
                }
            });
        }
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
        String jobNameForMultibranchProject = jobName != null
                ? jobName.contains("/") ? jobName.substring(0, jobName.lastIndexOf('/')) : jobName
                : null;

        // If item is not a 'Folder', then it is a Multibranch pipeline job
        TopLevelItem item =
                jenkins != null ? jenkins.getItemByFullName(jobNameForMultibranchProject, TopLevelItem.class) : null;

        // If 'item' is an instanceof 'Folder', it is either 'WorkflowJob' or 'FreestyleJob'
        // Then try to get the item type with actual 'jobName'
        if (item instanceof Folder) {
            item = jenkins != null ? jenkins.getItemByFullName(jobName, TopLevelItem.class) : null;
        }

        if (item != null) {
            return item.getClass().getSimpleName();
        } else {
            return "UnknownJobType";
        }
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

    public static boolean isBoolean(String value) {
        return value.equals("true") || value.equals("false");
    }
}
