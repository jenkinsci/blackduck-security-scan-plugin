package io.jenkins.plugins.security.scan.service.scan.coverity;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.input.blackducksca.Install;
import io.jenkins.plugins.security.scan.input.coverity.*;
import io.jenkins.plugins.security.scan.input.detect.Config;
import io.jenkins.plugins.security.scan.input.detect.Execution;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CoverityParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public CoverityParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean hasAllMandatoryCoverityParams(Map<String, Object> coverityParameters) {
        if (coverityParameters == null || coverityParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = getCoverityMissingMandatoryParams(coverityParameters);

        if (missingMandatoryParams.isEmpty()) {
            logger.info("Coverity parameters are validated successfully");
            return true;
        } else {
            logger.error(
                    ApplicationConstants.REQUIRED_PARAMETERS_FOR_SPECIFIC_SCAN_TYPE_IS_MISSING,
                    missingMandatoryParams.toString(), SecurityProduct.COVERITY.getProductLabel());
            return false;
        }
    }

    private List<String> getCoverityMissingMandatoryParams(Map<String, Object> coverityParameters) {
        List<String> missingMandatoryParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.COVERITY_URL_KEY,
                        ApplicationConstants.COVERITY_USER_KEY,
                        ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                .forEach(key -> {
                    boolean isKeyValid = coverityParameters.containsKey(key)
                            && coverityParameters.get(key) != null
                            && !coverityParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingMandatoryParams.add(key);
                    }
                });

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            missingMandatoryParams.addAll(getCoverityMissingMandatoryParamsForFreeStyleAndPipeline(coverityParameters));
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

            logger.error(
                    ApplicationConstants.REQUIRED_PARAMETERS_FOR_SPECIFIC_JOB_TYPE_IS_MISSING,
                    missingMandatoryParams, jobTypeName);
        }
    }

    private List<String> getCoverityMissingMandatoryParamsForFreeStyleAndPipeline(
            Map<String, Object> coverityParameters) {
        List<String> missingParamsForFreeStyleAndPipeline = new ArrayList<>();

        Arrays.asList(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, ApplicationConstants.COVERITY_STREAM_NAME_KEY)
                .forEach(key -> {
                    boolean isKeyValid = coverityParameters.containsKey(key)
                            && coverityParameters.get(key) != null
                            && !coverityParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingParamsForFreeStyleAndPipeline.add(key);
                    }
                });

        return missingParamsForFreeStyleAndPipeline;
    }

    public Coverity prepareCoverityObjectForBridge(Map<String, Object> coverityParameters) {
        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());

        setUrl(coverityParameters, coverity);
        setUser(coverityParameters, coverity);
        setPassPhrase(coverityParameters, coverity);
        setProjectName(coverityParameters, coverity);
        setStreamName(coverityParameters, coverity);

        setCoverityPolicyView(coverityParameters, coverity);
        setCoverityInstallDirectory(coverityParameters, coverity);
        setCoverityPrComment(coverityParameters, coverity);
        setVersion(coverityParameters, coverity);
        setCoverityLocal(coverityParameters, coverity);
        setWaitForScan(coverityParameters, coverity);

        setArbitaryInputs(coverityParameters, coverity);

        return coverity;
    }

    private void setProjectName(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_PROJECT_NAME_KEY)) {
            coverity.getConnect()
                    .getCoverityProject()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        } else {
            String repositoryName = RepositoryDetailsHolder.getRepositoryName();
            coverity.getConnect().getCoverityProject().setName(repositoryName);
            logger.info("Coverity Project Name: " + repositoryName);
        }
    }

    private void setStreamName(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_STREAM_NAME_KEY)) {
            coverity.getConnect()
                    .getStream()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_STREAM_NAME_KEY)
                            .toString()
                            .trim());
        } else {
            String repositoryName = RepositoryDetailsHolder.getRepositoryName();
            String branchName = envVars.get(ApplicationConstants.ENV_BRANCH_NAME_KEY);
            String targetBranchName = envVars.get(ApplicationConstants.ENV_CHANGE_TARGET_KEY);
            boolean isPullRequest = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null;

            String defaultStreamName = isPullRequest ? targetBranchName : branchName;

            if (repositoryName != null && defaultStreamName != null) {
                String coveritySteamName = repositoryName.concat("-").concat(defaultStreamName);
                coverity.getConnect().getStream().setName(coveritySteamName);
                logger.info("Coverity Stream Name: " + coveritySteamName);
            }
        }
    }

    private void setPassPhrase(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_PASSPHRASE_KEY)) {
            coverity.getConnect()
                    .getUser()
                    .setPassword(coverityParameters
                            .get(ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                            .toString()
                            .trim());
        }
    }

    private void setUser(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_USER_KEY)) {
            coverity.getConnect()
                    .getUser()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_USER_KEY)
                            .toString()
                            .trim());
        }
    }

    private void setUrl(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_URL_KEY)) {
            coverity.getConnect()
                    .setUrl(coverityParameters
                            .get(ApplicationConstants.COVERITY_URL_KEY)
                            .toString()
                            .trim());
        }
    }

    private void setVersion(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_VERSION_KEY)) {
            coverity.setVersion(coverityParameters
                    .get(ApplicationConstants.COVERITY_VERSION_KEY)
                    .toString()
                    .trim());
        }
    }

    public Coverity setArbitaryInputs(Map<String, Object> coverityParameters, Coverity coverity) {
        coverity = setBuildCommand(coverityParameters, coverity);
        coverity = setCleanCommand(coverityParameters, coverity);
        coverity = setConfigCommand(coverityParameters, coverity);
        coverity = setArgs(coverityParameters, coverity);
        coverity = setExecutionPath(coverityParameters, coverity);

        return coverity;
    }

    private void setCoverityLocal(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_LOCAL_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_LOCAL_KEY)
                    .toString()
                    .trim();
            if (value.equals("true") || value.equals("false")) {
                coverity.setLocal(Boolean.parseBoolean(value));
            }
        }
    }

    private void setCoverityPrComment(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY)) {
            String isEnabled = coverityParameters
                    .get(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY)
                    .toString()
                    .trim();
            if (isEnabled.equals("true")) {
                boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
                if (isPullRequestEvent) {
                    Automation automation = new Automation();
                    automation.setPrComment(true);
                    coverity.setAutomation(automation);
                } else {
                    logger.info(ApplicationConstants.COVERITY_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
                }
            }
        }
    }

    private void setCoverityInstallDirectory(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                Install install = new Install();
                install.setDirectory(value);
                coverity.setInstall(install);
            }
        }
    }

    private void setCoverityPolicyView(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_POLICY_VIEW_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_POLICY_VIEW_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                Policy policy = new Policy();
                policy.setView(value);
                coverity.getConnect().setPolicy(policy);
            }
        }
    }

    private void setWaitForScan(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_WAITFORSCAN_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_WAITFORSCAN_KEY)
                    .toString()
                    .trim();
            if (value.equals("true") || value.equals("false")) {
                coverity.setWaitForScan(Boolean.parseBoolean(value));
            }
        }
    }

    private Coverity setBuildCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                if (coverity == null) {
                    coverity = new Coverity();
                }
                Build build = new Build();
                build.setCommand(value);
                coverity.setBuild(build);
            }
        }
        return coverity;
    }

    private Coverity setCleanCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                if (coverity == null) {
                    coverity = new Coverity();
                }
                Clean clean = new Clean();
                clean.setCommand(value);
                coverity.setClean(clean);
            }
        }
        return coverity;
    }

    private Coverity setConfigCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_CONFIG_PATH_KEY)) {
            String value = coverityParameters
                    .get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                if (coverity == null) {
                    coverity = new Coverity();
                }
                Config config = new Config();
                config.setPath(value);
                coverity.setConfig(config);
            }
        }
        return coverity;
    }

    private Coverity setArgs(Map<String, Object> coverityParameters, Coverity coverity) {
        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_ARGS_KEY)) {
            if (coverity == null) {
                coverity = new Coverity();
            }
            coverity.setArgs(coverityParameters
                    .get(ApplicationConstants.COVERITY_ARGS_KEY)
                    .toString()
                    .trim());
        }
        return coverity;
    }

    private Coverity setExecutionPath(Map<String, Object> scanParameters, Coverity coverity) {
        if (scanParameters.containsKey(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY)) {
            String installationPath = scanParameters
                    .get(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY)
                    .toString()
                    .trim();
            if (!installationPath.isBlank()) {
                if (coverity == null) {
                    coverity = new Coverity();
                }
                Execution execution = new Execution();
                execution.setPath(installationPath);
                coverity.setExecution(execution);
            }
        }
        return coverity;
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> coverityParameters) {
        Project project = null;

        if (coverityParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY)) {
            project = new Project();

            String projectDirectory = coverityParameters
                    .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                    .toString()
                    .trim();
            project.setDirectory(projectDirectory);
        }
        return project;
    }
}
