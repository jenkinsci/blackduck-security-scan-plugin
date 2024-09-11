package io.jenkins.plugins.security.scan.service.scan.polaris;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.polaris.Parent;
import io.jenkins.plugins.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.security.scan.input.polaris.Prcomment;
import io.jenkins.plugins.security.scan.input.polaris.Test;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.project.Source;
import io.jenkins.plugins.security.scan.input.report.File;
import io.jenkins.plugins.security.scan.input.report.Issue;
import io.jenkins.plugins.security.scan.input.report.Reports;
import io.jenkins.plugins.security.scan.input.report.Sarif;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PolarisParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public PolarisParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean hasAllMandatoryCoverityParams(Map<String, Object> polarisParameters) {
        if (polarisParameters == null || polarisParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = getPolarisMissingMandatoryParams(polarisParameters);

        if (missingMandatoryParams.isEmpty()) {
            logger.info("Polaris parameters are validated successfully");
            return true;
        } else {
            logger.error(missingMandatoryParams + " - required parameters for Polaris is missing");
            return false;
        }
    }

    private List<String> getPolarisMissingMandatoryParams(Map<String, Object> polarisParameters) {
        List<String> missingMandatoryParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.POLARIS_SERVER_URL_KEY,
                        ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                        ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)
                .forEach(key -> {
                    boolean isKeyValid = polarisParameters.containsKey(key)
                            && polarisParameters.get(key) != null
                            && !polarisParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingMandatoryParams.add(key);
                    }
                });

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            missingMandatoryParams.addAll(getPolarisMissingMandatoryParamsForFreeStyleAndPipeline(polarisParameters));
        }

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

            logger.error(missingMandatoryParams + " - required parameters for " + jobTypeName + " job type is missing");
        }
    }

    private List<String> getPolarisMissingMandatoryParamsForFreeStyleAndPipeline(
            Map<String, Object> polarisParameters) {
        List<String> missingParamsForFreeStyleAndPipeline = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.POLARIS_APPLICATION_NAME_KEY,
                        ApplicationConstants.POLARIS_PROJECT_NAME_KEY,
                        ApplicationConstants.POLARIS_BRANCH_NAME_KEY)
                .forEach(key -> {
                    boolean isKeyValid = polarisParameters.containsKey(key)
                            && polarisParameters.get(key) != null
                            && !polarisParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingParamsForFreeStyleAndPipeline.add(key);
                    }
                });

        return missingParamsForFreeStyleAndPipeline;
    }

    public Polaris preparePolarisObjectForBridge(Map<String, Object> polarisParameters) {
        Polaris polaris = new Polaris();
        Prcomment prcomment = new Prcomment();

        setServerUrl(polarisParameters, polaris);
        setAccessToken(polarisParameters, polaris);
        setAssessmentTypes(polarisParameters, polaris);
        setApplicationName(polarisParameters, polaris);
        setProjectName(polarisParameters, polaris);
        setBranchName(polarisParameters, polaris);

        setTriage(polarisParameters, polaris);
        setTestScaType(polarisParameters, polaris);
        setPolarisPrCommentInputs(polarisParameters, prcomment, polaris);
        setAssessmentMode(polarisParameters, polaris);
        setWaitForScan(polarisParameters, polaris);

        setSarif(polarisParameters, polaris);

        return polaris;
    }

    private void setServerUrl(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_SERVER_URL_KEY)) {
            polaris.setServerUrl(polarisParameters
                    .get(ApplicationConstants.POLARIS_SERVER_URL_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setAccessToken(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)) {
            polaris.setAccessToken(polarisParameters
                    .get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setAssessmentTypes(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)) {
            String assessmentTypesValue = polarisParameters
                    .get(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)
                    .toString()
                    .trim();
            if (!assessmentTypesValue.isEmpty()) {
                List<String> assessmentTypes = Stream.of(
                                assessmentTypesValue.toUpperCase().split(","))
                        .map(String::trim)
                        .collect(Collectors.toList());
                polaris.getAssessmentTypes().setTypes(assessmentTypes);
            }
        }
    }

    private void setApplicationName(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY)) {
            polaris.getApplicationName()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY)
                            .toString()
                            .trim());
        } else {
            String repoName = RepositoryDetailsHolder.getRepositoryName();
            polaris.getApplicationName().setName(repoName);
            logger.info("Polaris Application Name: " + repoName);
        }
    }

    private void setProjectName(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PROJECT_NAME_KEY)) {
            polaris.getPolarisProject()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        } else {
            String repoName = RepositoryDetailsHolder.getRepositoryName();
            polaris.getPolarisProject().setName(repoName);
            logger.info("Polaris Project Name: " + repoName);
        }
    }

    private void setBranchName(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_BRANCH_NAME_KEY)) {
            polaris.getBranch()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY)
                            .toString()
                            .trim());
        } else {
            boolean isPullRequest = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null;
            String branchName = isPullRequest
                    ? envVars.get(ApplicationConstants.ENV_CHANGE_BRANCH_KEY)
                    : envVars.get(ApplicationConstants.ENV_BRANCH_NAME_KEY);
            polaris.getBranch().setName(branchName);
            logger.info("Polaris Branch Name: " + branchName);
        }
    }

    private void setTriage(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_TRIAGE_KEY)) {
            polaris.setTriage(polarisParameters
                    .get(ApplicationConstants.POLARIS_TRIAGE_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setTestScaType(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY)) {
            Test test = new Test();
            polaris.setTest(test);
            polaris.getTest()
                    .getSca()
                    .setType(polarisParameters
                            .get(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY)
                            .toString()
                            .trim());
        }
    }

    private void setSarif(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY)
                && envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) == null) {
            Sarif sarif = prepareSarifObject(polarisParameters);
            polaris.setReports(new Reports());
            polaris.getReports().setSarif(sarif);
        }
    }

    private void setAssessmentMode(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY)) {
            String assessmentModeValue = polarisParameters
                    .get(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY)
                    .toString()
                    .trim();
            if (!assessmentModeValue.isEmpty()) {
                polaris.getAssessmentTypes().setMode(assessmentModeValue);
            }
        }
    }

    private void setPolarisPrCommentInputs(
            Map<String, Object> polarisParameters, Prcomment prcomment, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)) {
            String isEnabled = polarisParameters
                    .get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)
                    .toString()
                    .trim();
            if (isEnabled.equals("true")) {
                boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
                if (isPullRequestEvent) {
                    prcomment.setEnabled(true);

                    if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY)) {
                        String prCommentSeveritiesValue = polarisParameters
                                .get(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY)
                                .toString()
                                .trim();
                        if (!prCommentSeveritiesValue.isEmpty()) {
                            List<String> prCommentSeverities = Arrays.asList(
                                    prCommentSeveritiesValue.toUpperCase().split(","));
                            prcomment.setSeverities(prCommentSeverities);
                        }
                    }

                    polaris.setPrcomment(prcomment);
                    setBranchParent(polarisParameters, polaris);
                } else {
                    logger.info(ApplicationConstants.POLARIS_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
                }
            }
        }
    }

    private static void setBranchParent(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY)) {
            String parentName = polarisParameters
                    .get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY)
                    .toString()
                    .trim();

            if (!parentName.isEmpty()) {
                Parent parent = new Parent();
                parent.setName(parentName);
                polaris.getBranch().setParent(parent);
            }
        }
    }
    private void setWaitForScan(Map<String, Object> polarisParameters, Polaris polaris) {
        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_WAITFORSCAN_KEY)) {
            String value = polarisParameters
                    .get(ApplicationConstants.POLARIS_WAITFORSCAN_KEY)
                    .toString()
                    .trim();
            if (value.equals("true") || value.equals("false")) {
                polaris.setWaitForScan(Boolean.parseBoolean(value));
            }
        }
    }


    public Project prepareProjectObjectForBridge(Map<String, Object> polarisParameters) {
        Project project = null;
        Source source = null;

        boolean hasProjectDirectory = polarisParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY);
        boolean hasSourceArchive = polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY);
        boolean hasPreserveSymLinks =
                polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY);
        boolean hasSourceExcludes = polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY);

        if (hasProjectDirectory || hasSourceArchive || hasPreserveSymLinks || hasSourceExcludes) {
            project = new Project();
            source = new Source();

            if (hasProjectDirectory) {
                String projectDirectory = polarisParameters
                        .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                        .toString()
                        .trim();
                project.setDirectory(projectDirectory);
            }

            if (hasSourceArchive) {
                String archive = polarisParameters
                        .get(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY)
                        .toString()
                        .trim();
                source.setArchive(archive);
                project.setSource(source);
            }

            if (hasPreserveSymLinks) {
                Boolean preserveSymLinks =
                        (Boolean) polarisParameters.get(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY);
                source.setPreserveSymLinks(preserveSymLinks);
                project.setSource(source);
            }

            if (hasSourceExcludes) {
                String sourceExcludesValue = polarisParameters
                        .get(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY)
                        .toString()
                        .trim();
                if (!sourceExcludesValue.isEmpty()) {
                    List<String> sourceExcludes = Stream.of(sourceExcludesValue.split(","))
                            .map(String::trim)
                            .collect(Collectors.toList());
                    source.setExcludes(sourceExcludes);
                    project.setSource(source);
                }
            }
        }

        return project;
    }

    public Sarif prepareSarifObject(Map<String, Object> sarifParameters) {
        Sarif sarif = new Sarif();

        if (sarifParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY)) {
            Boolean isReports_sarif_create =
                    (Boolean) sarifParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY);
            sarif.setCreate(isReports_sarif_create);
        }
        if (sarifParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY)) {
            String reports_sarif_file_path =
                    (String) sarifParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY);
            if (reports_sarif_file_path != null) {
                sarif.setFile(new File());
                sarif.getFile().setPath(reports_sarif_file_path);
            }
        }
        if (sarifParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY)) {
            String reports_sarif_severities =
                    (String) sarifParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY);
            String[] reports_sarif_severitiesInput =
                    reports_sarif_severities.toUpperCase().split(",");
            List<String> severities = Arrays.stream(reports_sarif_severitiesInput)
                    .map(String::trim)
                    .collect(Collectors.toList());
            if (!severities.isEmpty()) {
                sarif.setSeverities(severities);
            }
        }
        if (sarifParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY)) {
            Boolean reports_sarif_groupSCAIssues =
                    (Boolean) sarifParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY);
            sarif.setGroupSCAIssues(reports_sarif_groupSCAIssues);
        }
        if (sarifParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY)) {
            String reports_sarif_issue_types =
                    (String) sarifParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY);
            String[] reports_sarif_issue_typesInput =
                    reports_sarif_issue_types.toUpperCase().split(",");
            List<String> issueTypes = Arrays.stream(reports_sarif_issue_typesInput)
                    .map(String::trim)
                    .collect(Collectors.toList());
            if (!issueTypes.isEmpty()) {
                sarif.setIssue(new Issue());
                sarif.getIssue().setTypes(issueTypes);
            }
        }

        return sarif;
    }
}
