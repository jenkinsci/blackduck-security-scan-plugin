package io.jenkins.plugins.security.scan.bridge;

import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;

public class BridgeDownloadParameters {
    private String bridgeDownloadUrl;
    private String bridgeDownloadVersion;
    private String bridgeInstallationPath;

    public BridgeDownloadParameters(FilePath workspace, TaskListener listener) {
        BridgeInstall bridgeInstall = new BridgeInstall(workspace, listener);
        this.bridgeDownloadUrl = ApplicationConstants.BRIDGE_ARTIFACTORY_URL;
        this.bridgeDownloadVersion = ApplicationConstants.BRIDGE_CLI_LATEST_VERSION;
        this.bridgeInstallationPath = bridgeInstall.defaultBridgeInstallationPath(workspace, listener);
    }

    public String getBridgeDownloadUrl() {
        return bridgeDownloadUrl;
    }

    public void setBridgeDownloadUrl(String bridgeDownloadUrl) {
        this.bridgeDownloadUrl = bridgeDownloadUrl;
    }

    public String getBridgeDownloadVersion() {
        return bridgeDownloadVersion;
    }

    public void setBridgeDownloadVersion(String bridgeDownloadVersion) {
        this.bridgeDownloadVersion = bridgeDownloadVersion;
    }

    public String getBridgeInstallationPath() {
        return bridgeInstallationPath;
    }

    public void setBridgeInstallationPath(String bridgeInstallationPath) {
        this.bridgeInstallationPath = bridgeInstallationPath;
    }
}
