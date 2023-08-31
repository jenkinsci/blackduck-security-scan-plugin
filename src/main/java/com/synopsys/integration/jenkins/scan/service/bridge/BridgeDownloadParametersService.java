/*
 * synopsys-security-scan-plugin
 *
 * Copyright (c) 2023 Synopsys, Inc.
 *
 * Use subject to the terms and conditions of the Synopsys End User Software License and Maintenance Agreement. All rights reserved worldwide.
 */
package com.synopsys.integration.jenkins.scan.service.bridge;

import com.synopsys.integration.jenkins.scan.bridge.BridgeDownloadParameters;
import com.synopsys.integration.jenkins.scan.global.ApplicationConstants;
import com.synopsys.integration.jenkins.scan.global.LogMessages;
import com.synopsys.integration.jenkins.scan.global.Utility;
import hudson.FilePath;
import hudson.model.TaskListener;
import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridgeDownloadParametersService {
    private final TaskListener listener;
    private final FilePath workspace;

    public BridgeDownloadParametersService(FilePath workspace, TaskListener listener) {
        this.workspace = workspace;
        this.listener = listener;
    }

    public boolean performBridgeDownloadParameterValidation(BridgeDownloadParameters bridgeDownloadParameters) {
        boolean validUrl = isValidUrl(bridgeDownloadParameters.getBridgeDownloadUrl());
        boolean validVersion = isValidVersion(bridgeDownloadParameters.getBridgeDownloadVersion());
        boolean validInstallationPath = isValidInstallationPath(bridgeDownloadParameters.getBridgeInstallationPath());

        if(validUrl && validVersion && validInstallationPath) {
            listener.getLogger().println("Bridge download parameters are validated successfully");
            return true;
        } else {
            listener.getLogger().println(LogMessages.INVALID_BRIDGE_DOWNLOAD_PARAMETERS);
            return false;
        }
    }

    public boolean isValidUrl(String url) {
        if (url.isEmpty()) {
            listener.getLogger().println(LogMessages.EMPTY_BRIDGE_DOWNLOAD_URL_PROVIDED);
            return false;
        }

        try {
            new URL(url);
            return true;
        } catch (Exception e) {
            listener.getLogger().printf(LogMessages.INVALID_BRIDGE_DOWNLOAD_URL_PROVIDED, e.getMessage());
            return false;
        }
    }

    public boolean isValidVersion(String version) {
        Pattern pattern = Pattern.compile("\\d+\\.\\d+\\.\\d+");
        Matcher matcher = pattern.matcher(version);
        if( matcher.matches() || version.equals(ApplicationConstants.SYNOPSYS_BRIDGE_LATEST_VERSION)) {
            return true;
        } else {
            listener.getLogger().println(LogMessages.INVALID_BRIDGE_DOWNLOAD_VERSION_PROVIDED);
            return false;
        }
    }

    public boolean isValidInstallationPath(String installationPath) {
        try {
            FilePath path = new FilePath(workspace.getChannel(), installationPath);
            FilePath parentPath = path.getParent();

            if (parentPath != null && parentPath.exists() && parentPath.isDirectory()) {
                FilePath tempFile = parentPath.createTempFile("temp", null);
                boolean isWritable = tempFile.delete();

                if (isWritable) {
                    return true;
                } else {
                    listener.getLogger().printf("The bridge installation parent path: %s is not writable %n", parentPath.toURI());
                    return false;
                }
            } else {
                if (parentPath == null || !parentPath.exists()) {
                    listener.getLogger().printf("The bridge installation parent path: %s doesn't exist %n", path.toURI());
                } else if (!parentPath.isDirectory()) {
                    listener.getLogger().printf("The bridge installation parent path: %s is not a directory %n", parentPath.toURI());
                }
                return false;
            }
        } catch (IOException | InterruptedException e) {
            listener.getLogger().println("An exception occurred while validating the installation path: " + e.getMessage());
            e.printStackTrace(listener.getLogger());
            return false;
        }
    }

    public BridgeDownloadParameters getBridgeDownloadParams(Map<String, Object> scanParameters, BridgeDownloadParameters bridgeDownloadParameters) {
        if (scanParameters.containsKey(ApplicationConstants.BRIDGE_INSTALLATION_PATH)) {
            bridgeDownloadParameters.setBridgeInstallationPath(
                    scanParameters.get(ApplicationConstants.BRIDGE_INSTALLATION_PATH).toString().trim());
        }

        if (scanParameters.containsKey(ApplicationConstants.BRIDGE_DOWNLOAD_URL)) {
            bridgeDownloadParameters.setBridgeDownloadUrl(
                    scanParameters.get(ApplicationConstants.BRIDGE_DOWNLOAD_URL).toString().trim());
        }
        else if (scanParameters.containsKey(ApplicationConstants.BRIDGE_DOWNLOAD_VERSION)) {
            String desiredVersion = scanParameters.get(ApplicationConstants.BRIDGE_DOWNLOAD_VERSION).toString().trim();
            String bridgeDownloadUrl = String.join("/", ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                    desiredVersion, getSynopsysBridgeZipFileName(desiredVersion));

            bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
            bridgeDownloadParameters.setBridgeDownloadVersion(desiredVersion);
        }
        else {
            String bridgeDownloadUrl = String.join("/", ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                    ApplicationConstants.SYNOPSYS_BRIDGE_LATEST_VERSION, getSynopsysBridgeZipFileName());
            bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
        }
        return bridgeDownloadParameters;
    }

    public String getPlatform() {
        String os = Utility.getAgentOs(workspace, listener);
        if (os.contains("win")) {
            return ApplicationConstants.PLATFORM_WINDOWS;
        } else if (os.contains("mac")) {
            return ApplicationConstants.PLATFORM_MAC;
        } else {
            return ApplicationConstants.PLATFORM_LINUX;
        }
    }

    public String getSynopsysBridgeZipFileName() {
        return ApplicationConstants.BRIDGE_BINARY.concat("-").concat(getPlatform()).concat(".zip");
    }
    public String getSynopsysBridgeZipFileName(String version) {
        return ApplicationConstants.BRIDGE_BINARY.concat("-").concat(version).concat("-").concat(getPlatform()).concat(".zip");
    }
}