package io.jenkins.plugins.security.scan.bridge;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class BridgeDownload {
    private final LoggerWrapper logger;
    private final FilePath workspace;
    private final EnvVars envVars;

    public BridgeDownload(FilePath workspace, TaskListener listener, EnvVars envVars) {
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public FilePath downloadBridgeCLI(String bridgeDownloadUrl, String bridgeInstallationPath)
            throws PluginExceptionHandler {
        FilePath bridgeZipFilePath = null;
        FilePath bridgeInstallationFilePath = new FilePath(workspace.getChannel(), bridgeInstallationPath);

        if (!checkIfBridgeUrlExists(bridgeDownloadUrl)) {
            logger.warn(ApplicationConstants.INVALID_BRIDGE_CLI_DOWNLOAD_URL, bridgeDownloadUrl);
        }

        int retryCount = 1;
        boolean downloadSuccess = false;

        while (!downloadSuccess && retryCount <= ApplicationConstants.BRIDGE_DOWNLOAD_MAX_RETRIES) {
            try {
                logger.info("Downloading Bridge CLI from: " + bridgeDownloadUrl);
                bridgeZipFilePath = downloadBridge(bridgeDownloadUrl, bridgeInstallationFilePath);

                if (bridgeZipFilePath != null) {
                    downloadSuccess = true;
                }
            } catch (InterruptedException e) {
                logger.error(ApplicationConstants.INTERRUPTED_WHILE_WAITING_TO_RETRY_BRIDGE_CLI_DOWNLOAD);
                Thread.currentThread().interrupt();
                throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_DOWNLOAD_FAILED);
            } catch (Exception e) {
                handleDownloadException(bridgeDownloadUrl, retryCount);
                retryCount++;
            }
        }

        if (!downloadSuccess) {
            logger.error(
                    ApplicationConstants.BRIDGE_DOWNLOAD_FAILED_AFTER_X_ATTEMPTS,
                    ApplicationConstants.BRIDGE_DOWNLOAD_MAX_RETRIES);
        }

        if (bridgeZipFilePath == null) {
            throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_DOWNLOAD_FAILED);
        }

        return bridgeZipFilePath;
    }

    private FilePath downloadBridge(String bridgeDownloadUrl, FilePath bridgeInstallationFilePath)
            throws InterruptedException, IOException {
        FilePath bridgeZipFilePath = bridgeInstallationFilePath.child(ApplicationConstants.BRIDGE_ZIP_FILE_FORMAT);
        HttpURLConnection connection = Utility.getHttpURLConnection(new URL(bridgeDownloadUrl), logger);

        if (connection != null) {
            bridgeZipFilePath.copyFrom(connection.getURL());
            logger.info("Bridge CLI successfully downloaded in: " + bridgeZipFilePath);
        }

        return bridgeZipFilePath;
    }

    private void handleDownloadException(String bridgeDownloadUrl, int retryCount) throws PluginExceptionHandler {
        int statusCode = getHttpStatusCode(bridgeDownloadUrl);

        if (terminateRetry(statusCode)) {
            logger.error(ApplicationConstants.BRIDGE_CLI_DOWNLOAD_FAILED_WITH_STATUS_CODE, statusCode);
            throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_DOWNLOAD_FAILED_AND_WONT_RETRY);
        }

        try {
            Thread.sleep(ApplicationConstants.INTERVAL_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS);
        } catch (InterruptedException ie) {
            logger.warn(ApplicationConstants.EXCEPTION_OCCURRED_IN_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS, ie.getMessage());
            Thread.currentThread().interrupt();
        }
        logger.warn(ApplicationConstants.BRIDGE_CLI_DOWNLOAD_FAILED_AND_ATTEMPT_TO_DOWNLOAD_AGAIN, retryCount);
    }

    public int getHttpStatusCode(String url) {
        int statusCode = -1;

        try {
            HttpURLConnection connection = Utility.getHttpURLConnection(new URL(url), logger);
            if (connection != null) {
                connection.setRequestMethod("HEAD");
                statusCode = connection.getResponseCode();
                connection.disconnect();
            }
        } catch (IOException e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_CHECKING_THE_HTTP_STATUS_CODE, e.getMessage());
        }

        return statusCode;
    }

    public boolean terminateRetry(int statusCode) {
        return statusCode == HttpURLConnection.HTTP_UNAUTHORIZED
                || statusCode == HttpURLConnection.HTTP_FORBIDDEN
                || statusCode == HttpURLConnection.HTTP_OK
                || statusCode == HttpURLConnection.HTTP_CREATED
                || statusCode == 416;
    }

    public boolean checkIfBridgeUrlExists(String bridgeDownloadUrl) {
        try {
            URL url = new URL(bridgeDownloadUrl);

            HttpURLConnection connection = Utility.getHttpURLConnection(url, logger);
            if (connection != null) {
                connection.setRequestMethod("HEAD");
                return (connection.getResponseCode() == HttpURLConnection.HTTP_OK);
            }
        } catch (Exception e) {
            logger.error(ApplicationConstants.EXCEPTION_WHILE_CHECKING_BRIDGE_URL_EXISTS_OR_NOT, e.getMessage());
        }
        return false;
    }
}
