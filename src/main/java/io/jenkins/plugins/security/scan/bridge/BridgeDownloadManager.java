package io.jenkins.plugins.security.scan.bridge;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.service.bridge.BridgeDownloadParametersService;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridgeDownloadManager {
    private final TaskListener listener;
    private final FilePath workspace;
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public BridgeDownloadManager(FilePath workspace, TaskListener listener, EnvVars envVars) {
        this.workspace = workspace;
        this.listener = listener;
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public void initiateBridgeDownloadAndUnzip(BridgeDownloadParameters bridgeDownloadParams)
            throws PluginExceptionHandler {
        BridgeDownload bridgeDownload = new BridgeDownload(workspace, listener, envVars);
        BridgeInstall bridgeInstall = new BridgeInstall(workspace, listener);
        BridgeDownloadParametersService bridgeDownloadParametersService =
                new BridgeDownloadParametersService(workspace, listener);

        String bridgeDownloadUrl = bridgeDownloadParams.getBridgeDownloadUrl();
        String bridgeInstallationPath = bridgeDownloadParametersService.preferredBridgeCLIInstalledPath(
                bridgeDownloadParams.getBridgeInstallationPath());

        bridgeInstall.verifyAndCreateInstallationPath(bridgeInstallationPath);

        FilePath bridgeZipPath = bridgeDownload.downloadBridgeCLI(bridgeDownloadUrl, bridgeInstallationPath);

        bridgeInstall.installBridgeCLI(bridgeZipPath, new FilePath(workspace.getChannel(), bridgeInstallationPath));
    }

    public boolean isBridgeDownloadRequired(BridgeDownloadParameters bridgeDownloadParameters) {
        String bridgeDownloadUrl = bridgeDownloadParameters.getBridgeDownloadUrl();
        String bridgeInstallationPath = bridgeDownloadParameters.getBridgeInstallationPath();

        String installedBridgeVersionFilePath;
        String os = Utility.getAgentOs(workspace, listener);
        if (os.contains("win")) {
            installedBridgeVersionFilePath =
                    String.join("\\", bridgeInstallationPath, ApplicationConstants.VERSION_FILE);
        } else {
            installedBridgeVersionFilePath =
                    String.join("/", bridgeInstallationPath, ApplicationConstants.VERSION_FILE);
        }

        String installedBridgeVersion = getBridgeVersionFromVersionFile(installedBridgeVersionFilePath);
        String latestBridgeVersion = getLatestBridgeVersionFromArtifactory(bridgeDownloadUrl);

        return !Objects.equals(installedBridgeVersion, latestBridgeVersion);
    }

    public boolean checkIfBridgeInstalled(String bridgeInstallationPath) {
        try {
            FilePath installationDirectory = new FilePath(workspace.getChannel(), bridgeInstallationPath);

            if (installationDirectory.exists() && installationDirectory.isDirectory()) {
                FilePath bridgeBinaryFile = installationDirectory.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE);
                FilePath bridgeBinaryFileWindows =
                        installationDirectory.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS);
                FilePath versionFile = installationDirectory.child(ApplicationConstants.VERSION_FILE);

                return (bridgeBinaryFile.exists() || bridgeBinaryFileWindows.exists()) && versionFile.exists();
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_CHECKING_IF_THE_BRIDGE_IS_INSTALLED, e.getMessage());
            Thread.currentThread().interrupt();
        }
        return false;
    }

    public String getBridgeVersionFromVersionFile(String versionFilePath) {
        try {
            FilePath file = new FilePath(workspace.getChannel(), versionFilePath);
            if (file.exists()) {
                String versionsFileContent = file.readToString();
                Matcher matcher = Pattern.compile("bridge-cli-bundle: (\\d+\\.\\d+\\.\\d+)")
                        .matcher(versionsFileContent);

                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (IOException | InterruptedException e) {
            logger.error(
                    ApplicationConstants.EXCEPTION_WHILE_EXTRACTING_BRIDGE_VERSION_FROM_VERSIONS_TXT, e.getMessage());
            Thread.currentThread().interrupt();
        }
        return null;
    }

    public String getLatestBridgeVersionFromArtifactory(String bridgeDownloadUrl) {
        if (Utility.isStringNullOrBlank(bridgeDownloadUrl)) return ApplicationConstants.NOT_AVAILABLE;

        String extractedVersionNumber = Utility.extractVersionFromUrl(bridgeDownloadUrl);
        if (extractedVersionNumber.equals(ApplicationConstants.NOT_AVAILABLE)) {
            String directoryUrl = getDirectoryUrl(bridgeDownloadUrl);
            if (isVersionFileAvailableInArtifactory(directoryUrl)) {
                String versionFilePath = downloadVersionFileFromArtifactory(directoryUrl);
                String latestVersion = getBridgeVersionFromVersionFile(versionFilePath);

                Utility.removeFile(versionFilePath, workspace, listener);

                return latestVersion;
            } else {
                return ApplicationConstants.NOT_AVAILABLE;
            }
        } else {
            return extractedVersionNumber;
        }
    }

    public String downloadVersionFileFromArtifactory(String directoryUrl) {
        String versionFileUrl = String.join("/", directoryUrl, ApplicationConstants.VERSION_FILE);
        String tempVersionFilePath = null;

        try {
            FilePath tempFilePath = workspace.createTempFile("versions", ".txt");
            URL url = new URL(versionFileUrl);

            HttpURLConnection connection = Utility.getHttpURLConnection(url, envVars, logger);
            if (connection != null) {
                tempFilePath.copyFrom(connection.getURL());
                tempVersionFilePath = tempFilePath.getRemote();
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_DOWNLOADING_VERSIONS_TXT, e.getMessage());
            Thread.currentThread().interrupt();
        }
        return tempVersionFilePath;
    }

    public boolean isVersionFileAvailableInArtifactory(String directoryUrl) {
        try {
            URL url = new URL(String.join("/", directoryUrl, ApplicationConstants.VERSION_FILE));

            HttpURLConnection connection = Utility.getHttpURLConnection(url, envVars, logger);
            if (connection != null) {
                connection.setRequestMethod("HEAD");
                return (connection.getResponseCode() >= 200 && connection.getResponseCode() < 300);
            }
        } catch (IOException e) {
            logger.error(
                    ApplicationConstants.EXCEPTION_WHILE_CHECKING_VERSIONS_TXT_IS_AVAILABLE_OR_NOT_IN_THE_URL,
                    e.getMessage());
        }
        return false;
    }

    public String getDirectoryUrl(String downloadUrl) {
        String directoryUrl = null;
        try {
            URI uri = new URI(downloadUrl);
            String path = uri.getPath();

            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            String directoryPath = path.substring(0, path.lastIndexOf('/'));
            directoryUrl =
                    uri.getScheme().concat("://").concat(uri.getAuthority()).concat(directoryPath);
        } catch (URISyntaxException e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_GETTING_DIRECTORY_URL_FROM_DOWNLOAD_URL, e.getMessage());
        }
        return directoryUrl;
    }
}
