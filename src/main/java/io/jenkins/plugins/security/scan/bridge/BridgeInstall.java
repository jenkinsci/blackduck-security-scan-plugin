package io.jenkins.plugins.security.scan.bridge;

import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.*;
import java.io.IOException;
import java.util.List;
import jenkins.model.Jenkins;

public class BridgeInstall {
    private final LoggerWrapper logger;
    private final FilePath workspace;

    public BridgeInstall(FilePath workspace, TaskListener listener) {
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
    }

    public void installBridgeCLI(FilePath bridgeZipPath, FilePath bridgeInstallationPath)
            throws PluginExceptionHandler {
        try {
            if (bridgeZipPath != null && bridgeInstallationPath != null) {
                logger.info("Unzipping Bridge CLI zip file from: %s", bridgeZipPath.getRemote());
                bridgeZipPath.unzip(bridgeInstallationPath);
                logger.info("Bridge CLI installed successfully in: %s", bridgeInstallationPath.getRemote());
            }
        } catch (IOException | InterruptedException e) {
            logger.error(Utility.generateMessage(
                    ApplicationConstants.UNZIPPING_BRIDGE_CLI_ZIP_FILE, List.of(e.getMessage())));
            Thread.currentThread().interrupt();
            throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_UNZIPPING_FAILED);
        }

        // Deleting the bridge zip file after unzipping
        try {
            if (bridgeZipPath != null) {
                bridgeZipPath.delete();
            }
        } catch (IOException | InterruptedException e) {
            logger.warn(Utility.generateMessage(
                    ApplicationConstants.EXCEPTION_WHILE_DELETING_BRIDGE_CLI_ZIP_FILE, List.of(e.getMessage())));
            Thread.currentThread().interrupt();
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
            logger.error(Utility.generateMessage(
                    ApplicationConstants.FAILED_TO_FETCH_PLUGINS_DEFAULT_INSTALLATION_PATH, List.of(e.getMessage())));
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
            logger.error(Utility.generateMessage(
                    ApplicationConstants.FAILED_TO_CREATE_DEFAULT_INSTALLATION_DIRECTORY,
                    List.of(directory.getRemote())));
            Thread.currentThread().interrupt();
        }
    }
}
