package io.jenkins.plugins.security.scan.service.bridge;

import com.fasterxml.jackson.core.Version;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridgeDownloadParametersService {
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final FilePath workspace;

    public BridgeDownloadParametersService(FilePath workspace, TaskListener listener) {
        this.workspace = workspace;
        this.listener = listener;
        this.logger = new LoggerWrapper(listener);
    }

    public boolean performBridgeDownloadParameterValidation(BridgeDownloadParameters bridgeDownloadParameters)
            throws PluginExceptionHandler {
        boolean validUrl = isValidUrl(bridgeDownloadParameters.getBridgeDownloadUrl());
        boolean validVersion = isValidVersion(bridgeDownloadParameters.getBridgeDownloadVersion());
        boolean validInstallationPath = isValidInstallationPath(bridgeDownloadParameters.getBridgeInstallationPath());

        if (validUrl && validVersion && validInstallationPath) {
            logger.info("Bridge download parameters are validated successfully");
            return true;
        } else {
            logger.error(ApplicationConstants.BRIDGE_DOWNLOAD_PARAMETERS_ARE_NOT_VALID);
            throw new PluginExceptionHandler(ErrorCode.INVALID_BRIDGE_DOWNLOAD_PARAMETERS);
        }
    }

    public boolean isValidUrl(String url) {
        if (url.isEmpty()) {
            logger.warn(ApplicationConstants.EMPTY_BRIDGE_CLI_URL);
            return false;
        }

        try {
            new URL(url);
            return true;
        } catch (MalformedURLException me) {
            logger.error(ApplicationConstants.INVALID_BRIDGE_CLI_URL, me.getMessage());
            return false;
        }
    }

    public boolean isValidVersion(String version) {
        Pattern pattern = Pattern.compile("\\d+\\.\\d+\\.\\d+");
        Matcher matcher = pattern.matcher(version);
        if (matcher.matches() || version.equals(ApplicationConstants.BRIDGE_CLI_LATEST_VERSION)) {
            return true;
        } else {
            logger.error(ApplicationConstants.BRIDGE_CLI_VERSION_NOT_FOUND, version);
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
                    logger.error(
                            ApplicationConstants.BRIDGE_INSTALLATION_PARENT_PATH_IS_NOT_WRITABLE, parentPath.toURI());
                    return false;
                }
            } else {
                if (parentPath == null || !parentPath.exists()) {
                    logger.error(
                            ApplicationConstants.BRIDGE_INSTALLATION_PARENT_PATH_DOES_NOT_EXIST,
                            path.toURI().toString());
                } else if (!parentPath.isDirectory()) {
                    logger.error(
                            ApplicationConstants.BRIDGE_INSTALLATION_PARENT_PATH_IS_NOT_A_DIRECTORY,
                            parentPath.toURI().toString());
                }
                return false;
            }
        } catch (IOException | InterruptedException e) {
            logger.error(ApplicationConstants.VALIDATING_THE_INSTALLATION_PATH_EXCEPTION, e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public BridgeDownloadParameters getBridgeDownloadParams(
            Map<String, Object> scanParameters, BridgeDownloadParameters bridgeDownloadParameters) {
        if (scanParameters.containsKey(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY)) {
            bridgeDownloadParameters.setBridgeInstallationPath(scanParameters
                    .get(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY)
                    .toString()
                    .trim());
        }

        boolean isNetworkAirgap = scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)
                && scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY).equals(true);

        if (scanParameters.containsKey(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL)) {
            bridgeDownloadParameters.setBridgeDownloadUrl(scanParameters
                    .get(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL)
                    .toString()
                    .trim());
            String extractedVersionNumber =
                    Utility.extractVersionFromUrl(bridgeDownloadParameters.getBridgeDownloadUrl());
            if (!extractedVersionNumber.equals(ApplicationConstants.NOT_AVAILABLE)) {
                bridgeDownloadParameters.setBridgeDownloadVersion(extractedVersionNumber);
            }

        } else if (scanParameters.containsKey(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION) && !isNetworkAirgap) {
            String desiredVersion = scanParameters
                    .get(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION)
                    .toString()
                    .trim();
            String bridgeDownloadUrl = String.join(
                    "/",
                    ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                    desiredVersion,
                    getBridgeZipFileName(desiredVersion));

            bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
            bridgeDownloadParameters.setBridgeDownloadVersion(desiredVersion);
        } else {
            if (!isNetworkAirgap) {
                String bridgeDownloadUrl = String.join(
                        "/",
                        ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                        ApplicationConstants.BRIDGE_CLI_LATEST_VERSION,
                        getBridgeZipFileName());
                bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
            }
        }
        return bridgeDownloadParameters;
    }

    public void updateBridgeInstallationPath(BridgeDownloadParameters bridgeDownloadParameters) {
        String separator = Utility.getDirectorySeparator(workspace, listener);
        String modifiedInstalationPath = bridgeDownloadParameters
                .getBridgeInstallationPath()
                .concat(separator)
                .concat(ApplicationConstants.DEFAULT_DIRECTORY_NAME)
                .concat("-")
                .concat(getPlatform(bridgeDownloadParameters.getBridgeDownloadVersion()));

        bridgeDownloadParameters.setBridgeInstallationPath(modifiedInstalationPath);
    }

    public String getPlatform(String version) {
        String os = Utility.getAgentOs(workspace, listener);
        if (os.contains("win")) {
            return ApplicationConstants.PLATFORM_WINDOWS;
        }
        String arch = Utility.getAgentOsArch(workspace, listener);
        boolean isMac = os.contains("mac");
        boolean isLinux = os.contains("linux");
        boolean isArm = arch.startsWith("arm") || arch.startsWith("aarch");

        if (isMac) {
            if (Objects.nonNull(version)
                    && !isVersionCompatibleForARMChips(
                            version, ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION)) {
                return ApplicationConstants.PLATFORM_MACOSX;
            }
            return isArm ? ApplicationConstants.PLATFORM_MAC_ARM : ApplicationConstants.PLATFORM_MACOSX;
        }

        if (isLinux) {
            if (Objects.nonNull(version)
                    && !isVersionCompatibleForARMChips(
                            version, ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION)) {
                return ApplicationConstants.PLATFORM_LINUX;
            }
            return isArm ? ApplicationConstants.PLATFORM_LINUX_ARM : ApplicationConstants.PLATFORM_LINUX;
        }

        return ApplicationConstants.PLATFORM_LINUX;
    }

    public String getBridgeZipFileName() {
        return ApplicationConstants.DEFAULT_DIRECTORY_NAME
                .concat("-")
                .concat(getPlatform(null))
                .concat(".zip");
    }

    public String getBridgeZipFileName(String version) {
        return ApplicationConstants.DEFAULT_DIRECTORY_NAME
                .concat("-")
                .concat(version)
                .concat("-")
                .concat(getPlatform(version))
                .concat(".zip");
    }

    public boolean isVersionCompatibleForARMChips(String version, String minCompatibleBridgeVersion) {
        if (version.equals(ApplicationConstants.BRIDGE_CLI_LATEST_VERSION)) {
            return true;
        }
        String[] inputVersionSplits = version.split("\\.");
        String[] minCompatibleArmVersionSplits = minCompatibleBridgeVersion.split("\\.");

        if (inputVersionSplits.length != 3 && minCompatibleArmVersionSplits.length != 3) {
            return false;
        }

        Version inputVersion = new Version(
                Integer.parseInt(inputVersionSplits[0]),
                Integer.parseInt(inputVersionSplits[1]),
                Integer.parseInt(inputVersionSplits[2]),
                null,
                null,
                null);
        Version minCompatibleArmVersion = new Version(
                Integer.parseInt(minCompatibleArmVersionSplits[0]),
                Integer.parseInt(minCompatibleArmVersionSplits[1]),
                Integer.parseInt(minCompatibleArmVersionSplits[2]),
                null,
                null,
                null);

        return inputVersion.compareTo(minCompatibleArmVersion) >= 0;
    }
}
