package io.jenkins.plugins.security.scan.bridge;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.*;
import java.io.IOException;
import jenkins.model.Jenkins;

public class BridgeInstall {
    private final LoggerWrapper logger;
    private final FilePath workspace;
    private final TaskListener listener;
    private final EnvVars envVars;

    public BridgeInstall(FilePath workspace, TaskListener listener, EnvVars envVars) {
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
        this.listener = listener;
        this.envVars = envVars;
    }

    public void installBridgeCLI(FilePath bridgeZipPath, BridgeDownloadParameters bridgeDownloadParameters)
            throws PluginExceptionHandler {

        String bridgeInstallationPath = bridgeDownloadParameters.getBridgeInstallationPath();
        String separator = Utility.getDirectorySeparator(workspace, listener);
        int lastIndex = bridgeDownloadParameters.getBridgeInstallationPath().lastIndexOf(separator);
        String subFolderName = "";
        if (lastIndex != -1) {
            subFolderName = bridgeInstallationPath.substring(lastIndex + 1);
            bridgeInstallationPath = bridgeInstallationPath.substring(0, lastIndex);
        }
        FilePath bridgeInstallationFilePath = new FilePath(workspace.getChannel(), bridgeInstallationPath);
        String osType = subFolderName.substring(subFolderName.lastIndexOf("-") + 1);
        String bridgeCLIDownloadVersion = bridgeDownloadParameters.getBridgeDownloadVersion();

        try {
            if (bridgeZipPath != null && bridgeInstallationFilePath.isDirectory()) {
                FilePath targetFolder = new FilePath(bridgeInstallationFilePath, subFolderName);
                handleExistingFolder(targetFolder);

                logger.info("Unzipping Bridge CLI zip file from: %s", bridgeZipPath.getRemote());
                bridgeZipPath.unzip(bridgeInstallationFilePath);
                logger.info("Bridge CLI installed successfully in: %s", bridgeInstallationFilePath.getRemote());

                handlePostUnzipping(
                        targetFolder,
                        bridgeInstallationFilePath,
                        osType,
                        bridgeCLIDownloadVersion,
                        bridgeDownloadParameters);
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.UNZIPPING_BRIDGE_CLI_ZIP_FILE, e.getMessage());
            Thread.currentThread().interrupt();
            throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_UNZIPPING_FAILED);
        }

        // Deleting the bridge zip file after unzipping
        try {
            if (bridgeZipPath != null) {
                bridgeZipPath.delete();
            }
        } catch (IOException | InterruptedException e) {
            logger.warn(ApplicationConstants.EXCEPTION_WHILE_DELETING_BRIDGE_CLI_ZIP_FILE, e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    private void handleExistingFolder(FilePath targetFolder) throws IOException, InterruptedException {
        if (targetFolder.exists()) {
            logger.info("Deleting previous Bridge CLI folder: %s", targetFolder.getRemote());
            targetFolder.deleteRecursive();
        }
    }

    private void handlePostUnzipping(
            FilePath targetFolder,
            FilePath bridgeInstallationFilePath,
            String osType,
            String bridgeCLIDownloadVersion,
            BridgeDownloadParameters bridgeDownloadParameters)
            throws IOException, InterruptedException {

        if (!bridgeCLIDownloadVersion.equals(ApplicationConstants.BRIDGE_CLI_LATEST_VERSION)) {
            // Define the expected unzipped folder name based on the download version
            String expectedFolderName =
                    ApplicationConstants.DEFAULT_DIRECTORY_NAME + "-" + bridgeCLIDownloadVersion + "-" + osType;
            FilePath unzippedFolder = new FilePath(bridgeInstallationFilePath, expectedFolderName);

            if (unzippedFolder.exists()) {
                if (!targetFolder.exists()) {
                    logger.info("Renaming folder %s to %s", unzippedFolder.getRemote(), targetFolder.getRemote());
                    unzippedFolder.renameTo(targetFolder);
                }
            } else {
                logger.warn("Expected folder '%s' not found after unzipping.", expectedFolderName);
            }
        } else {
            String installedBridgeVersionFilePath;
            if (osType.contains("win")) {
                installedBridgeVersionFilePath =
                        String.join("\\", targetFolder.getRemote(), ApplicationConstants.VERSION_FILE);
            } else {
                installedBridgeVersionFilePath =
                        String.join("/", targetFolder.getRemote(), ApplicationConstants.VERSION_FILE);
            }
            BridgeDownloadManager bridgeDownloadManager = new BridgeDownloadManager(workspace, listener, envVars);
            String installedBridgeVersion =
                    bridgeDownloadManager.getBridgeVersionFromVersionFile(installedBridgeVersionFilePath);
            bridgeDownloadParameters.setBridgeDownloadVersion(installedBridgeVersion);
        }
    }

    public String defaultBridgeInstallationPath(FilePath workspace, TaskListener listener) {

        logger.println("-------------------------------- Connection to node --------------------------------");

        Jenkins jenkins = Jenkins.getInstanceOrNull();
        String separator = Utility.getDirectorySeparator(workspace, listener);
        String defaultInstallationPath = null;

        if (jenkins != null && workspace.isRemote()) {
            logger.info("Jenkins job is running on agent node remotely");
        } else {
            logger.info("Jenkins job is running on master node");
        }

        try {
            defaultInstallationPath = workspace.act(new HomeDirectoryTask(separator));
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.FAILED_TO_FETCH_PLUGINS_DEFAULT_INSTALLATION_PATH, e.getMessage());
            Thread.currentThread().interrupt();
        }

        return defaultInstallationPath;
    }

    public void verifyAndCreateInstallationPath(String bridgeInstallationPath) {
        FilePath directory = new FilePath(workspace.getChannel(), bridgeInstallationPath);
        try {
            if (!directory.exists()) {
                directory.mkdirs();
                logger.info("Created bridge installation directory at: " + directory.getRemote());
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.FAILED_TO_CREATE_DEFAULT_INSTALLATION_DIRECTORY, directory.getRemote());
            Thread.currentThread().interrupt();
        }
    }
}
