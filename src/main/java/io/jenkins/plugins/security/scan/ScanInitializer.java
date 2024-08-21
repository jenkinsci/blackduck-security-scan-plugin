package io.jenkins.plugins.security.scan;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.bridge.BridgeDownloadManager;
import io.jenkins.plugins.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.service.ParameterMappingService;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LogMessages;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.bridge.BridgeDownloadParametersService;
import io.jenkins.plugins.security.scan.service.scan.ScanParametersService;

import java.util.*;

public class ScanInitializer {
    private final SecurityScanner scanner;
    private final FilePath workspace;
    private final TaskListener listener;
    private final EnvVars envVars;
    private final LoggerWrapper logger;

    public ScanInitializer(
            SecurityScanner scanner, FilePath workspace, EnvVars envVars, TaskListener listener) {
        this.scanner = scanner;
        this.workspace = workspace;
        this.listener = listener;
        this.envVars = envVars;
        this.logger = new LoggerWrapper(listener);
    }

    public int initializeScanner(Map<String, Object> scanParameters) throws PluginExceptionHandler {
        ScanParametersService scanParametersService = new ScanParametersService(listener);
        BridgeDownloadParameters bridgeDownloadParameters = new BridgeDownloadParameters(workspace, listener);
        BridgeDownloadParametersService bridgeDownloadParametersService =
                new BridgeDownloadParametersService(workspace, listener);
        BridgeDownloadParameters bridgeDownloadParams =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParameters, bridgeDownloadParameters);

        logMessagesForParameters(scanParameters, scanParametersService.getSecurityProducts(scanParameters));

        scanParametersService.performScanParameterValidation(scanParameters, envVars);

        bridgeDownloadParametersService.performBridgeDownloadParameterValidation(bridgeDownloadParams);

        BridgeDownloadManager bridgeDownloadManager = new BridgeDownloadManager(workspace, listener, envVars);
        boolean isNetworkAirGap = checkNetworkAirgap(scanParameters);
        boolean isBridgeInstalled =
                bridgeDownloadManager.checkIfBridgeInstalled(bridgeDownloadParams.getBridgeInstallationPath());
        boolean isBridgeDownloadRequired = true;

        handleNetworkAirgap(isNetworkAirGap, bridgeDownloadParams, isBridgeInstalled);

        if (isBridgeInstalled) {
            isBridgeDownloadRequired = bridgeDownloadManager.isBridgeDownloadRequired(bridgeDownloadParams);
        }

        handleBridgeDownload(isBridgeDownloadRequired, isNetworkAirGap, bridgeDownloadParams, bridgeDownloadManager);

        FilePath bridgeInstallationPath =
                new FilePath(workspace.getChannel(), bridgeDownloadParams.getBridgeInstallationPath());

        return scanner.runScanner(scanParameters, bridgeInstallationPath);
    }

    private boolean checkNetworkAirgap(Map<String, Object> scanParameters) {
        return scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)
                && scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY).equals(true);
    }

    private void handleNetworkAirgap(
            boolean isNetworkAirgap, BridgeDownloadParameters bridgeDownloadParams, boolean isBridgeInstalled)
            throws PluginExceptionHandler {
        if (isNetworkAirgap && !bridgeDownloadParams.getBridgeDownloadUrl().contains(".zip") && !isBridgeInstalled) {
            logger.error("Bridge CLI could not be found in " + bridgeDownloadParams.getBridgeInstallationPath());
            throw new PluginExceptionHandler(ErrorCode.BRIDGE_CLI_NOT_FOUND_IN_PROVIDED_PATH);
        }

        if (isNetworkAirgap) {
            logger.info("Network Air Gap mode is enabled");
        }
    }

    public void handleBridgeDownload(
            boolean isBridgeDownloadRequired,
            boolean isNetworkAirgap,
            BridgeDownloadParameters bridgeDownloadParams,
            BridgeDownloadManager bridgeDownloadManager)
            throws PluginExceptionHandler {
        if (isBridgeDownloadRequired
                && bridgeDownloadParams.getBridgeDownloadUrl().contains(".zip")) {
            if (isNetworkAirgap) {
                logger.warn(
                        "Bridge-CLI will be downloaded from the provided custom URL. Make sure the network is reachable");
            }
            bridgeDownloadManager.initiateBridgeDownloadAndUnzip(bridgeDownloadParams);
        } else {
            logger.info("Bridge download is not required. Found installed in: "
                    + bridgeDownloadParams.getBridgeInstallationPath());
            logger.println(LogMessages.DASHES);
        }
    }

    public void logMessagesForParameters(Map<String, Object> scanParameters, Set<String> securityProducts) {
        logger.println("-------------------------- Parameter Validation Initiated --------------------------");

        Map<String, Object> parametersCopy = new HashMap<>(scanParameters);

        logMessagesForProductParameters(parametersCopy, securityProducts);

        logMessagesForAdditionalParameters(parametersCopy);

        if ((Objects.equals(parametersCopy.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY), true)
                        || Objects.equals(
                                parametersCopy.get(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY), true))
                && envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null) {
            logger.info("SARIF report create/upload is ignored for PR/MR scans");
        }
    }

    private void logMessagesForProductParameters(Map<String, Object> scanParameters, Set<String> securityProducts) {
        logger.info(LogMessages.LOG_DASH + ApplicationConstants.PRODUCT_KEY + " = " + securityProducts.toString());

        // Warning message for blackduck stage
        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())) {
            logger.warn(SecurityProduct.BLACKDUCK.name().toLowerCase()
                    .concat(" product is deprecated and will be removed in future. Please use "
                    .concat(SecurityProduct.BLACKDUCKSCA.name())
                            .concat(" and its corresponding parameters instead.")));
        }

        for (String product : securityProducts) {
            String securityProduct = product.toLowerCase();

            logger.info("Parameters for %s:", securityProduct);
            logParameters(scanParameters, securityProduct);

            logger.println(LogMessages.DASHES);
        }
    }

    private void logParameters(Map<String, Object> scanParameters, String securityProduct) {
        for (Map.Entry<String, Object> entry : scanParameters.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (shouldLogParameter(securityProduct, key)) {
                if (isSensitiveKey(key)) {
                    value = LogMessages.ASTERISKS;
                }
                logger.info(LogMessages.LOG_DASH + key + " = " + value.toString());
            }

            logWarningForDeprecatedParameters();
        }
    }

    private boolean shouldLogParameter(String securityProduct, String key) {
        List<String> arbitraryParamList = ApplicationConstants.ARBITRARY_PARAM_KEYS;
        return key.contains(securityProduct)
                || key.equals(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                || key.startsWith("detect_")
                || (securityProduct.equals(SecurityProduct.POLARIS.name().toLowerCase())
                        && (key.startsWith("project_") || arbitraryParamList.contains(key)))
                || (securityProduct.equals(SecurityProduct.SRM.name().toLowerCase())
                        && (key.equals(ApplicationConstants.SRM_SCA_DETECT_EXECUTION_PATH_KEY)
                                || key.equals(ApplicationConstants.SRM_SAST_EXECUTION_PATH_KEY)
                                || arbitraryParamList.contains(key)));
    }

    private boolean isSensitiveKey(String key) {
        return key.equals(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                || key.equals(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)
                || key.equals(ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                || key.equals(ApplicationConstants.SRM_APIKEY_KEY);
    }

    private void logMessagesForAdditionalParameters(Map<String, Object> scanParameters) {
        boolean additionalParamsFound = false;

        for (Map.Entry<String, Object> entry : scanParameters.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("bridgecli_")
                    || key.equals(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY)
                    || key.equals(ApplicationConstants.NETWORK_AIRGAP_KEY)
                    || key.equals(ApplicationConstants.MARK_BUILD_STATUS)) {
                if (!additionalParamsFound) {
                    logger.info("Parameters for additional configuration:");
                    additionalParamsFound = true;
                }
                Object value = entry.getValue();
                logger.info(LogMessages.LOG_DASH + key + " = " + value.toString());
            }
        }
    }

    private void logWarningForDeprecatedParameters() {
        if (!ParameterMappingService.DEPRECATED_PARAMETERS.isEmpty()) {
            logger.warn(ParameterMappingService.DEPRECATED_PARAMETERS + " is/are deprecated and will be removed in future. " +
                    "Check documentation for new parameters: " + ApplicationConstants.SYNOPSYS_SECURITY_SCAN_PLUGIN_DOCS_URL);

            ParameterMappingService.DEPRECATED_PARAMETERS.clear();
        }
    }
}
