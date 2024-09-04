package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.blackducksca.Automation;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.blackducksca.Failure;
import io.jenkins.plugins.security.scan.input.blackducksca.Scan;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.report.File;
import io.jenkins.plugins.security.scan.input.report.Reports;
import io.jenkins.plugins.security.scan.input.report.Sarif;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

        setUrl(blackDuckSCAParameters, blackDuckSCA);
        setToken(blackDuckSCAParameters, blackDuckSCA);
        setScanFailureSeverities(blackDuckSCAParameters, blackDuckSCA);
        setAutomationPrComment(blackDuckSCAParameters, automation, blackDuckSCA);
        setSarif(blackDuckSCAParameters, blackDuckSCA);

        return blackDuckSCA;
    }

    private void setUrl(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_URL_KEY)) {
            blackDuckSCA.setUrl(blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_URL_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setToken(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)) {
            blackDuckSCA.setToken(blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setScanFailureSeverities(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY)
                    .toString()
                    .trim();
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
    }

    private void setAutomationPrComment(
            Map<String, Object> blackDuckSCAParameters, Automation automation, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)
                    .toString()
                    .trim();
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
    }

    private void setSarif(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY)
                && envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) == null) {
            Sarif sarif = prepareSarifObject(blackDuckSCAParameters);
            blackDuckSCA.setReports(new Reports());
            blackDuckSCA.getReports().setSarif(sarif);
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

    public Sarif prepareSarifObject(Map<String, Object> sarifParameters) {
        Sarif sarif = new Sarif();

        if (sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY)) {
            Boolean isReports_sarif_create =
                    (Boolean) sarifParameters.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY);
            sarif.setCreate(isReports_sarif_create);
        }
        if (sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY)) {
            String reports_sarif_file_path =
                    (String) sarifParameters.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY);
            if (reports_sarif_file_path != null) {
                sarif.setFile(new File());
                sarif.getFile().setPath(reports_sarif_file_path);
            }
        }
        if (sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY)) {
            String reports_sarif_severities =
                    (String) sarifParameters.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY);
            String[] reports_sarif_severitiesInput =
                    reports_sarif_severities.toUpperCase().split(",");
            List<String> severities = Arrays.stream(reports_sarif_severitiesInput)
                    .map(String::trim)
                    .collect(Collectors.toList());
            if (!severities.isEmpty()) {
                sarif.setSeverities(severities);
            }
        }
        if (sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY)) {
            Boolean reports_sarif_groupSCAIssues =
                    (Boolean) sarifParameters.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY);
            sarif.setGroupSCAIssues(reports_sarif_groupSCAIssues);
        }
        return sarif;
    }
}
