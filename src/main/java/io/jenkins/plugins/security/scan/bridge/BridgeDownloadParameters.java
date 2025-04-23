package io.jenkins.plugins.security.scan.bridge;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;

import java.util.Objects;

/**
 * Encapsulates parameters required for downloading and installing the Bridge CLI.
 */
public class BridgeDownloadParameters {

    private final String bridgeDownloadUrl;
    private final String bridgeDownloadVersion;
    private final String bridgeInstallationPath;

    /**
     * Constructs BridgeDownloadParameters using workspace context and environment variables.
     *
     * @param workspace Jenkins workspace
     * @param listener  TaskListener for logging
     * @param envVars   Environment variables
     */
    public BridgeDownloadParameters(FilePath workspace, TaskListener listener, EnvVars envVars) {
        Objects.requireNonNull(workspace, "Workspace must not be null");
        Objects.requireNonNull(listener, "Listener must not be null");
        Objects.requireNonNull(envVars, "Environment variables must not be null");

        this.bridgeDownloadUrl = ApplicationConstants.BRIDGE_ARTIFACTORY_URL;
        this.bridgeDownloadVersion = ApplicationConstants.BRIDGE_CLI_LATEST_VERSION;
        this.bridgeInstallationPath = new BridgeInstall(workspace, listener, envVars)
                .defaultBridgeInstallationPath(workspace, listener);
    }

    public String getBridgeDownloadUrl() {
        return bridgeDownloadUrl;
    }

    public String getBridgeDownloadVersion() {
        return bridgeDownloadVersion;
    }

    public String getBridgeInstallationPath() {
        return bridgeInstallationPath;
    }

    @Override
    public String toString() {
        return "BridgeDownloadParameters{" +
                "bridgeDownloadUrl='" + bridgeDownloadUrl + '\'' +
                ", bridgeDownloadVersion='" + bridgeDownloadVersion + '\'' +
                ", bridgeInstallationPath='" + bridgeInstallationPath + '\'' +
                '}';
    }
}
