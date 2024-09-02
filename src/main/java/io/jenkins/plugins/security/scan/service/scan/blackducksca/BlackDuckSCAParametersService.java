package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.blackducksca.*;
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

    public boolean isValidBlackDuckParameters(Map<String, Object> blackDuckSCAParameters) {
        if (blackDuckSCAParameters == null || blackDuckSCAParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = new ArrayList<>();

        Arrays.asList(ApplicationConstants.BLACKDUCKSCA_URL_KEY, ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                .forEach(key -> {
                    boolean isKeyValid = blackDuckSCAParameters.containsKey(key)
                            && blackDuckSCAParameters.get(key) != null
                            && !blackDuckSCAParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingMandatoryParams.add(key);
                    }
                });

        if (missingMandatoryParams.isEmpty()) {
            logger.info("Black Duck SCA parameters are validated successfully");
            return true;
        } else {
            logger.error(missingMandatoryParams + " - required parameters for Black Duck SCA is missing");
            return false;
        }
    }

    public BlackDuckSCA prepareBlackDuckSCAObjectForBridge(Map<String, Object> blackDuckSCAParameters) {
        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        Automation automation = new Automation();

        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_URL_KEY)) {
            blackDuckSCA.setUrl(blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_URL_KEY)
                    .toString()
                    .trim());
        }

        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)) {
            blackDuckSCA.setToken(blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                    .toString()
                    .trim());
        }

        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)
                    .toString()
                    .trim();
            setScanFailureSeverities(blackDuckSCA, value);
        }

        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)
                    .toString()
                    .trim();
            setAutomationPrComment(blackDuckSCA, value, automation);
        }

        return blackDuckSCA;
    }

    private void setScanFailureSeverities(BlackDuckSCA blackDuckSCA, String value) {
        if (!value.isBlank()) {
            List<String> failureSeverities = new ArrayList<>();
            String[] failureSeveritiesInput = value.toUpperCase().split(",");

            for (String input : failureSeveritiesInput) {
                failureSeverities.add(input.trim());
            }
            if (!failureSeverities.isEmpty()) {
                Failure failure = new Failure();
                Scan scan = new Scan();
                failure.setSeverities(failureSeverities);
                scan.setFailure(failure);
                blackDuckSCA.setScan(scan);
            }
        }
    }

    private void setAutomationPrComment(BlackDuckSCA blackDuckSCA, String value, Automation automation) {
        if (value.equals("true")) {
            boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
            if (isPullRequestEvent) {
                automation.setPrComment(true);
                blackDuckSCA.setAutomation(automation);
            } else {
                logger.info(ApplicationConstants.BLACKDUCK_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> blackDuckSCAParameters) {
        Project project = null;

        if (blackDuckSCAParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY)) {
            project = new Project();

            String projectDirectory = blackDuckSCAParameters
                    .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                    .toString()
                    .trim();
            project.setDirectory(projectDirectory);
        }
        return project;
    }
}
