package io.jenkins.plugins.security.scan.service.scan.srm;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.srm.Branch;
import io.jenkins.plugins.security.scan.input.srm.SRM;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SRMParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public SRMParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean hasAllMandatorySrmParams(Map<String, Object> srmParameters) {
        if (srmParameters == null || srmParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = getSrmMissingMandatoryParams(srmParameters);

        if (missingMandatoryParams.isEmpty()) {
            logger.info("SRM parameters are validated successfully");
            return true;
        } else {
            logger.error(missingMandatoryParams + " - required parameters for SRM is missing");
            return false;
        }
    }

    private List<String> getSrmMissingMandatoryParams(Map<String, Object> srmParameters) {
        List<String> missingMandatoryParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.SRM_URL_KEY,
                        ApplicationConstants.SRM_APIKEY_KEY,
                        ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)
                .forEach(key -> {
                    boolean isKeyValid = srmParameters.containsKey(key)
                            && srmParameters.get(key) != null
                            && !srmParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingMandatoryParams.add(key);
                    }
                });

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            boolean isProjectNameValid = srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_NAME_KEY)
                    && srmParameters.get(ApplicationConstants.SRM_PROJECT_NAME_KEY) != null
                    && !srmParameters
                            .get(ApplicationConstants.SRM_PROJECT_NAME_KEY)
                            .toString()
                            .isEmpty();

            boolean isProjectIdValid = srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_ID_KEY)
                    && srmParameters.get(ApplicationConstants.SRM_PROJECT_ID_KEY) != null
                    && !srmParameters
                            .get(ApplicationConstants.SRM_PROJECT_ID_KEY)
                            .toString()
                            .isEmpty();

            if (!isProjectNameValid && !isProjectIdValid) {
                logger.error("One of " + ApplicationConstants.SRM_PROJECT_NAME_KEY + " or "
                        + ApplicationConstants.SRM_PROJECT_ID_KEY + " must be present.");
                missingMandatoryParams.add(ApplicationConstants.SRM_PROJECT_ID_KEY);
            }
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

    public SRM prepareSrmObjectForBridge(Map<String, Object> srmParameters) {
        SRM srm = new SRM();
        Branch branch = new Branch();

        setUrl(srmParameters, srm);
        setApiKey(srmParameters, srm);
        setAssessmentTypes(srmParameters, srm);
        setProjectName(srmParameters, srm);
        setProjectId(srmParameters, srm);
        setBranchName(srmParameters, branch, srm);
        setBranchParent(srmParameters, branch, srm);

        return srm;
    }

    private void setUrl(Map<String, Object> srmParameters, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_URL_KEY)) {
            srm.setUrl(srmParameters
                    .get(ApplicationConstants.SRM_URL_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setApiKey(Map<String, Object> srmParameters, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_APIKEY_KEY)) {
            srm.setApikey(srmParameters
                    .get(ApplicationConstants.SRM_APIKEY_KEY)
                    .toString()
                    .trim());
        }
    }

    private void setProjectName(Map<String, Object> srmParameters, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_NAME_KEY)) {
            srm.getSrmProject()
                    .setName(srmParameters
                            .get(ApplicationConstants.SRM_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        } else if (!srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_ID_KEY)) {
            String repoName = RepositoryDetailsHolder.getRepositoryName();
            srm.getSrmProject().setName(repoName);
            logger.info("SRM Project Name: " + repoName);
        }
    }

    private void setProjectId(Map<String, Object> srmParameters, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_ID_KEY)) {
            srm.getSrmProject()
                    .setId(srmParameters
                            .get(ApplicationConstants.SRM_PROJECT_ID_KEY)
                            .toString()
                            .trim());
        }
    }

    private void setBranchName(Map<String, Object> srmParameters, Branch branch, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_BRANCH_NAME_KEY)) {
            branch.setName(srmParameters
                    .get(ApplicationConstants.SRM_BRANCH_NAME_KEY)
                    .toString()
                    .trim());
            srm.setBranch(branch);
        }
    }

    private void setBranchParent(Map<String, Object> srmParameters, Branch branch, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_BRANCH_PARENT_KEY)) {
            branch.setParent(srmParameters
                    .get(ApplicationConstants.SRM_BRANCH_PARENT_KEY)
                    .toString()
                    .trim());
            srm.setBranch(branch);
        }
    }

    private void setAssessmentTypes(Map<String, Object> srmParameters, SRM srm) {
        if (srmParameters.containsKey(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)) {
            String assessmentTypesValue = srmParameters
                    .get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)
                    .toString()
                    .trim();
            if (!assessmentTypesValue.isEmpty()) {
                List<String> assessmentTypes = Stream.of(
                                assessmentTypesValue.toUpperCase().split(","))
                        .map(String::trim)
                        .collect(Collectors.toList());
                srm.getAssessmentTypes().setTypes(assessmentTypes);
            }
        }
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> srmParameters) {
        Project project = null;

        if (srmParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY)) {
            project = new Project();

            String projectDirectory = srmParameters
                    .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                    .toString()
                    .trim();
            project.setDirectory(projectDirectory);
        }
        return project;
    }
}
