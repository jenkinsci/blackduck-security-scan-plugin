package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.blackduck.*;
import io.jenkins.plugins.security.scan.input.project.Project;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class BlackDuckSCAParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public BlackDuckSCAParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean isValidBlackDuckParameters(Map<String, Object> blackDuckParameters) {
        if (blackDuckParameters == null || blackDuckParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(ApplicationConstants.BLACKDUCKSCA_URL_KEY, ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                .forEach(key -> {
                    boolean isKeyValid = blackDuckParameters.containsKey(key)
                            && blackDuckParameters.get(key) != null
                            && !blackDuckParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        if (invalidParams.isEmpty()) {
            logger.info("BlackDuck parameters are validated successfully");
            return true;
        } else {
            logger.error("BlackDuck parameters are not valid");
            logger.error("Invalid BlackDuck parameters: " + invalidParams);
            return false;
        }
    }

    public BlackDuck prepareBlackDuckObjectForBridge(Map<String, Object> blackDuckParameters) {
        BlackDuck blackDuck = new BlackDuck();
        Scan scan = new Scan();
        Automation automation = new Automation();

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_URL_KEY)) {
            blackDuck.setUrl(blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_URL_KEY)
                    .toString()
                    .trim());
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)) {
            blackDuck.setToken(blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                    .toString()
                    .trim());
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)
                    .toString()
                    .trim();
            setInstallDirectory(blackDuck, value);
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.DETECT_SCAN_FULL_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.DETECT_SCAN_FULL_KEY)
                    .toString()
                    .trim();
            setScanFull(blackDuck, value, scan);
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)
                    .toString()
                    .trim();
            setScanFailureSeverities(blackDuck, value, scan);
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)
                    .toString()
                    .trim();
            setAutomationPrComment(blackDuck, value, automation);
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_DOWNLOAD_URL_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_DOWNLOAD_URL_KEY)
                    .toString()
                    .trim();
            setDownloadUrl(blackDuck, String.valueOf(Integer.parseInt(value)));
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY)
                    .toString()
                    .trim();
            setSearchDepth(blackDuck, Integer.parseInt(value));
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY)
                    .toString()
                    .trim();
            setConfigPath(blackDuck, value);
        }

        if (blackDuckParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_ARGS_KEY)) {
            String value = blackDuckParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_ARGS_KEY)
                    .toString()
                    .trim();
            blackDuck.setArgs(value);
        }

        return blackDuck;
    }

    private void setScanFailureSeverities(BlackDuck blackDuck, String value, Scan scan) {
        if (!value.isBlank()) {
            List<String> failureSeverities = new ArrayList<>();
            String[] failureSeveritiesInput = value.toUpperCase().split(",");

            for (String input : failureSeveritiesInput) {
                failureSeverities.add(input.trim());
            }
            if (!failureSeverities.isEmpty()) {
                Failure failure = new Failure();
                failure.setSeverities(failureSeverities);
                scan.setFailure(failure);
                blackDuck.setScan(scan);
            }
        }
    }

    private void setInstallDirectory(BlackDuck blackDuck, String value) {
        if (value != null) {
            Install install = new Install();
            install.setDirectory(value);
            blackDuck.setInstall(install);
        }
    }

    private void setScanFull(BlackDuck blackDuck, String value, Scan scan) {
        if (isBoolean(value)) {
            scan.setFull(Boolean.parseBoolean(value));
            blackDuck.setScan(scan);
        }
    }

    private void setAutomationPrComment(BlackDuck blackDuck, String value, Automation automation) {
        if (value.equals("true")) {
            boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
            if (isPullRequestEvent) {
                automation.setPrComment(true);
                blackDuck.setAutomation(automation);
            } else {
                logger.info(ApplicationConstants.BLACKDUCK_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }
    }

    private void setDownloadUrl(BlackDuck blackDuck, String value) {
        if (value != null) {
            Download download = new Download();
            download.setUrl(value);
            blackDuck.setDownload(download);
        }
    }

    private void setSearchDepth(BlackDuck blackDuck, Integer value) {
        if (value != null) {
            Search search = new Search();
            search.setDepth(value);
            blackDuck.setSearch(search);
        }
    }

    private void setConfigPath(BlackDuck blackDuck, String value) {
        if (value != null) {
            Config config = new Config();
            config.setPath(value);
            blackDuck.setConfig(config);
        }
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> polarisParameters) {
        Project project = null;

        if (polarisParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY)) {
            project = new Project();

            String projectDirectory = polarisParameters
                    .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                    .toString()
                    .trim();
            project.setDirectory(projectDirectory);
        }
        return project;
    }

    private boolean isBoolean(String value) {
        return value.equals("true") || value.equals("false");
    }
}
