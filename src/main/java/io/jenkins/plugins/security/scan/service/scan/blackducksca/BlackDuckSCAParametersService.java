package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.input.blackducksca.*;
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

    public boolean hasAllMandatoryBlackduckSCAParams(Map<String, Object> blackDuckSCAParameters) {
        if (blackDuckSCAParameters == null || blackDuckSCAParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = getBlackDuckSCAMissingMandatoryParams(blackDuckSCAParameters);

        if (missingMandatoryParams.isEmpty()) {
            logger.info("Black Duck SCA parameters are validated successfully");
            return true;
        } else {
            logger.error(
                    ApplicationConstants.REQUIRED_PARAMETERS_FOR_SPECIFIC_SCAN_TYPE_IS_MISSING,
                    missingMandatoryParams.toString(),
                    SecurityProduct.BLACKDUCKSCA.getProductLabel());
            return false;
        }
    }

    private List<String> getBlackDuckSCAMissingMandatoryParams(Map<String, Object> blackDuckSCAParameters) {
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

        String jobType = Utility.jenkinsJobType(envVars);

        showErrorMessageForJobType(missingMandatoryParams, jobType);

        return missingMandatoryParams;
    }

    private void showErrorMessageForJobType(List<String> missingMandatoryParams, String jobType) {
        if (!missingMandatoryParams.isEmpty()) {
            String jobTypeName;
            if (jobType.equalsIgnoreCase(ApplicationConstants.FREESTYLE_JOB_TYPE_NAME)) {
                jobTypeName = "FreeStyle";
            } else if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
                jobTypeName = "Multibranch Pipeline";
            } else {
                jobTypeName = "Pipeline";
            }

            logger.error(
                    ApplicationConstants.REQUIRED_PARAMETERS_FOR_SPECIFIC_JOB_TYPE_IS_MISSING,
                    missingMandatoryParams,
                    jobTypeName);
        }
    }

    public BlackDuckSCA prepareBlackDuckSCAObjectForBridge(Map<String, Object> blackDuckSCAParameters) {
        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        Automation automation = new Automation();

        setUrl(blackDuckSCAParameters, blackDuckSCA);
        setToken(blackDuckSCAParameters, blackDuckSCA);
        setScanFull(blackDuckSCAParameters, blackDuckSCA);
        setScanFailureSeverities(blackDuckSCAParameters, blackDuckSCA);
        setAutomationPrComment(blackDuckSCAParameters, automation, blackDuckSCA);
        setFixPr(blackDuckSCAParameters, blackDuckSCA);
        setSarif(blackDuckSCAParameters, blackDuckSCA);
        setWaitForScan(blackDuckSCAParameters, blackDuckSCA);

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

    private void setFixPr(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY)
                    .toString()
                    .trim();
            if (value.equals("true")) {
                boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
                if (isPullRequestEvent) {
                    logger.info(ApplicationConstants.BLACKDUCK_FIXPR_INFO_FOR_NON_PR_SCANS);
                } else {
                    FixPr fixPr = prepareFixPrObject(blackDuckSCAParameters);
                    blackDuckSCA.setFixPr(fixPr);
                }
            }
        }
    }

    private void setScanFull(Map<String, Object> scanParameters, BlackDuckSCA blackDuckSCA) {
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_SCAN_FULL_KEY)) {
            String product = scanParameters
                    .get(ApplicationConstants.PRODUCT_KEY)
                    .toString()
                    .trim()
                    .toUpperCase();
            if ((product.contains(SecurityProduct.BLACKDUCK.name())
                    || product.contains(SecurityProduct.BLACKDUCKSCA.name()))) {
                String value = scanParameters
                        .get(ApplicationConstants.BLACKDUCKSCA_SCAN_FULL_KEY)
                        .toString()
                        .trim();
                if (Utility.isBoolean(value)) {
                    Scan scan = new Scan();
                    scan.setFull(Boolean.parseBoolean(value));
                    blackDuckSCA.setScan(scan);
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

    private void setWaitForScan(Map<String, Object> blackDuckSCAParameters, BlackDuckSCA blackDuckSCA) {
        if (blackDuckSCAParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY)) {
            String value = blackDuckSCAParameters
                    .get(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY)
                    .toString()
                    .trim();
            if (value.equals("true") || value.equals("false")) {
                blackDuckSCA.setWaitForScan(Boolean.parseBoolean(value));
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

    public Sarif prepareSarifObject(Map<String, Object> sarifParameters) {
        Sarif sarif = new Sarif();
        boolean shouldCreateSarifInDefaultPath =
                sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY)
                        && !sarifParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY);

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
        if (shouldCreateSarifInDefaultPath) {
            sarif.setFile(new File());
            sarif.getFile()
                    .setPath(ApplicationConstants.DEFAULT_BLACKDUCKSCA_SARIF_REPORT_FILE_PATH
                            + ApplicationConstants.SARIF_REPORT_FILENAME);
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

    public FixPr prepareFixPrObject(Map<String, Object> fixPrParameters) {
        FixPr fixPr = new FixPr();
        fixPr.setEnabled(true);

        if (fixPrParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_FIXPR_MAXCOUNT_KEY)) {
            Integer blackducksca_fixpr_maxCount =
                    (Integer) fixPrParameters.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_MAXCOUNT_KEY);
            fixPr.setMaxCount(blackducksca_fixpr_maxCount);
        }

        if (fixPrParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_FIXPR_FILTER_SEVERITIES_KEY)) {
            String fixPR_filter_severities =
                    (String) fixPrParameters.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_FILTER_SEVERITIES_KEY);
            String[] fixPR_filter_severitiesInput =
                    fixPR_filter_severities.toUpperCase().split(",");
            List<String> severities = Arrays.stream(fixPR_filter_severitiesInput)
                    .map(String::trim)
                    .collect(Collectors.toList());
            if (!severities.isEmpty()) {
                Filter filter = new Filter();
                filter.setSeverities(severities);
                fixPr.setFilter(filter);
            }
        }

        if (fixPrParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_FIXPR_USEUPGRADEGUIDANCE_KEY)) {
            String fixPR_UseUpgradeGuidance =
                    (String) fixPrParameters.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_USEUPGRADEGUIDANCE_KEY);
            String[] fixPR_UseUpgradeGuidanceInput =
                    fixPR_UseUpgradeGuidance.toUpperCase().split(",");
            List<String> guidance = Arrays.stream(fixPR_UseUpgradeGuidanceInput)
                    .map(String::trim)
                    .collect(Collectors.toList());
            if (!guidance.isEmpty()) {
                fixPr.setUseUpgradeGuidance(guidance);
            }
        }
        return fixPr;
    }
}
