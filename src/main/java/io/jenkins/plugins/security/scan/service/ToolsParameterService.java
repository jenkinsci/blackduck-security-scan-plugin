package io.jenkins.plugins.security.scan.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.BridgeParams;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.input.BridgeInput;
import io.jenkins.plugins.security.scan.input.NetworkAirGap;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.detect.Detect;
import io.jenkins.plugins.security.scan.input.polaris.Parent;
import io.jenkins.plugins.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.security.scan.input.srm.SRM;
import io.jenkins.plugins.security.scan.service.scan.ScanParametersService;
import io.jenkins.plugins.security.scan.service.scan.blackducksca.BlackDuckSCAParametersService;
import io.jenkins.plugins.security.scan.service.scan.blackducksca.DetectParametersService;
import io.jenkins.plugins.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.security.scan.service.scan.polaris.PolarisParametersService;
import io.jenkins.plugins.security.scan.service.scan.srm.SRMParametersService;
import io.jenkins.plugins.security.scan.service.scm.SCMRepositoryService;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ToolsParameterService {
    private final TaskListener listener;
    private final EnvVars envVars;
    private final FilePath workspace;
    private static final String DATA_KEY = "data";
    private final LoggerWrapper logger;

    public ToolsParameterService(TaskListener listener, EnvVars envVars, FilePath workspace) {
        this.listener = listener;
        this.envVars = envVars;
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
    }

    public List<String> getCommandLineArgs(Map<String, Object> scanParameters, FilePath bridgeInstallationPath)
            throws PluginExceptionHandler {
        List<String> commandLineArgs = new ArrayList<>();

        commandLineArgs.add(getBridgeRunCommand(bridgeInstallationPath));

        commandLineArgs.addAll(getSecurityProductSpecificCommands(scanParameters));

        if (Objects.equals(scanParameters.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY), true)) {
            commandLineArgs.add(BridgeParams.DIAGNOSTICS_OPTION);
        }

        return commandLineArgs;
    }

    private String getBridgeRunCommand(FilePath bridgeInstallationPath) {
        String os = Utility.getAgentOs(workspace, listener);

        if (os.contains("win")) {
            return bridgeInstallationPath
                    .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS)
                    .getRemote();
        } else {
            return bridgeInstallationPath
                    .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE)
                    .getRemote();
        }
    }

    private List<String> getSecurityProductSpecificCommands(Map<String, Object> scanParameters)
            throws PluginExceptionHandler {
        ScanParametersService scanParametersService = new ScanParametersService(listener);
        Set<String> securityProducts = scanParametersService.getSecurityProducts(scanParameters);

        List<String> scanCommands = new ArrayList<>();
        Object scmObject = getScmObject(scanParameters);

        setBlackDuckScaCommands(scanParameters, securityProducts, scanCommands, scmObject);
        setCoverityCommands(scanParameters, securityProducts, scanCommands, scmObject);
        setPolarisCommands(scanParameters, securityProducts, scanCommands, scmObject);
        setSrmCommands(scanParameters, securityProducts, scanCommands, scmObject);

        return scanCommands;
    }

    private void setBlackDuckScaCommands(
            Map<String, Object> scanParameters,
            Set<String> securityProducts,
            List<String> scanCommands,
            Object scmObject) {
        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())
                || securityProducts.contains(SecurityProduct.BLACKDUCKSCA.name())) {
            BlackDuckSCAParametersService blackDuckSCAParametersService =
                    new BlackDuckSCAParametersService(listener, envVars);
            BlackDuckSCA blackDuckSCA =
                    blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(scanParameters);
            Project project = blackDuckSCAParametersService.prepareProjectObjectForBridge(scanParameters);

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.BLACKDUCKSCA_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(prepareBridgeInputJson(
                    scanParameters,
                    blackDuckSCA,
                    scmObject,
                    ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX,
                    project));
        }
    }

    private void setCoverityCommands(
            Map<String, Object> scanParameters,
            Set<String> securityProducts,
            List<String> scanCommands,
            Object scmObject) {
        if (securityProducts.contains(SecurityProduct.COVERITY.name())) {
            CoverityParametersService coverityParametersService = new CoverityParametersService(listener, envVars);
            Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(scanParameters);
            Project project = coverityParametersService.prepareProjectObjectForBridge(scanParameters);

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.COVERITY_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(prepareBridgeInputJson(
                    scanParameters, coverity, scmObject, ApplicationConstants.COVERITY_INPUT_JSON_PREFIX, project));
        }
    }

    private void setPolarisCommands(
            Map<String, Object> scanParameters,
            Set<String> securityProducts,
            List<String> scanCommands,
            Object scmObject) {
        if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            PolarisParametersService polarisParametersService = new PolarisParametersService(listener, envVars);
            Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(scanParameters);
            Project project = polarisParametersService.prepareProjectObjectForBridge(scanParameters);

            if (polaris.getBranch().getParent() == null) {
                String defaultParentBranchName = envVars.get(ApplicationConstants.ENV_CHANGE_TARGET_KEY);
                if (defaultParentBranchName != null) {
                    logger.info("Polaris Branch Parent Name: " + defaultParentBranchName);
                    Parent parent = new Parent();
                    parent.setName(defaultParentBranchName);
                    polaris.getBranch().setParent(parent);
                }
            }

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.POLARIS_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(prepareBridgeInputJson(
                    scanParameters, polaris, scmObject, ApplicationConstants.POLARIS_INPUT_JSON_PREFIX, project));
        }
    }

    private void setSrmCommands(
            Map<String, Object> scanParameters,
            Set<String> securityProducts,
            List<String> scanCommands,
            Object scmObject) {
        if (securityProducts.contains(SecurityProduct.SRM.name())) {
            SRMParametersService srmParametersService = new SRMParametersService(listener, envVars);
            SRM srm = srmParametersService.prepareSrmObjectForBridge(scanParameters);
            Project project = srmParametersService.prepareProjectObjectForBridge(scanParameters);

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.SRM_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(prepareBridgeInputJson(
                    scanParameters, srm, scmObject, ApplicationConstants.SRM_INPUT_JSON_PREFIX, project));
        }
    }

    public String prepareBridgeInputJson(
            Map<String, Object> scanParameters,
            Object scanObject,
            Object scmObject,
            String jsonPrefix,
            Project project) {
        BridgeInput bridgeInput = new BridgeInput();

        setScanObject(bridgeInput, scanObject, scanParameters);

        setProjectObject(bridgeInput, project);

        setScmObject(bridgeInput, scmObject, scanParameters);

        setNetworkAirGapObject(bridgeInput, scanParameters);

        setDetectObject(scanParameters, bridgeInput);

        String inputJson = createBridgeInputJson(bridgeInput);

        return writeInputJsonToFile(inputJson, jsonPrefix);
    }

    private String createBridgeInputJson(BridgeInput bridgeInput) {
        Map<String, Object> inputJsonMap = new HashMap<>();
        inputJsonMap.put(DATA_KEY, bridgeInput);

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);

        try {
            return mapper.writeValueAsString(inputJsonMap);
        } catch (Exception e) {
            logger.error(ApplicationConstants.CREATING_INPUT_JSON_FILE_EXCEPTION, e.getMessage());
        }
        return null;
    }

    private void setDetectObject(Map<String, Object> scanParameters, BridgeInput bridgeInput) {
        DetectParametersService detectParametersService = new DetectParametersService();
        Detect detect = detectParametersService.prepareDetectObject(scanParameters);
        if (detect != null) {
            bridgeInput.setDetect(detect);
        }
    }

    private void setNetworkAirGapObject(BridgeInput bridgeInput, Map<String, Object> scanParameters) {
        if (scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)) {
            Boolean isNetworkAirGap = (Boolean) scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY);
            NetworkAirGap networkAirGap = new NetworkAirGap();
            networkAirGap.setAirgap(isNetworkAirGap);
            bridgeInput.setNetworkAirGap(networkAirGap);
        }
    }

    private Object getScmObject(Map<String, Object> scanParameters) throws PluginExceptionHandler {
        SCMRepositoryService scmRepositoryService = new SCMRepositoryService(listener, envVars);
        Object scmObject = null;
        String jobType = Utility.jenkinsJobType(envVars);
        if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            scmObject = scmRepositoryService.fetchSCMRepositoryDetails(
                    Utility.installedBranchSourceDependencies(), scanParameters);
        }
        return scmObject;
    }

    private void setScmObject(BridgeInput bridgeInput, Object scmObject, Map<String, Object> scanParameters) {
        boolean isPrCommentSet = isPrCommentValueSet(scanParameters);
        boolean isFixPrSet = isFixPrValueSet(scanParameters);
        boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
        if ((isPrCommentSet && isPullRequestEvent) || (isFixPrSet && !isPullRequestEvent)) {
            if (scmObject instanceof Bitbucket) {
                bridgeInput.setBitbucket((Bitbucket) scmObject);
            } else if (scmObject instanceof Github) {
                bridgeInput.setGithub((Github) scmObject);
            } else if (scmObject instanceof Gitlab) {
                bridgeInput.setGitlab((Gitlab) scmObject);
            }
        }
    }

    private void setScanObject(BridgeInput bridgeInput, Object scanObject, Map<String, Object> scanParameters) {
        if (scanObject instanceof BlackDuckSCA) {
            BlackDuckSCA blackDuckSCA = (BlackDuckSCA) scanObject;
            bridgeInput.setBlackDuckSCA(blackDuckSCA);
        } else if (scanObject instanceof Coverity) {
            Coverity coverity = (Coverity) scanObject;
            bridgeInput.setCoverity(coverity);
        } else if (scanObject instanceof Polaris) {
            Polaris polaris = (Polaris) scanObject;
            bridgeInput.setPolaris(polaris);
            setSastArbitaryInputs(bridgeInput, scanParameters);
        } else if (scanObject instanceof SRM) {
            SRM srm = (SRM) scanObject;
            bridgeInput.setSrm(srm);
            setSastArbitaryInputs(bridgeInput, scanParameters);
        }
    }

    private void setProjectObject(BridgeInput bridgeInput, Project project) {
        if (project != null) {
            bridgeInput.setProject(project);
        }
    }

    private void setSastArbitaryInputs(BridgeInput bridgeInput, Map<String, Object> scanParameters) {
        CoverityParametersService coverityParametersService = new CoverityParametersService(listener, envVars);
        Coverity coverity = coverityParametersService.setArbitaryInputs(scanParameters, null);
        if (coverity != null) {
            bridgeInput.setCoverity(coverity);
        }
    }

    public String writeInputJsonToFile(String inputJson, String jsonPrefix) {
        String inputJsonPath = null;

        try {
            FilePath parentWorkspacePath = workspace.getParent();
            if (parentWorkspacePath != null) {
                FilePath tempFile = parentWorkspacePath.createTempFile(jsonPrefix, ".json");
                tempFile.write(inputJson, StandardCharsets.UTF_8.name());
                inputJsonPath = tempFile.getRemote();
            } else {
                logger.error(ApplicationConstants.FAILED_TO_CREATE_JSON_FILE_IN_WORKSPACE_PARENT_PATH);
            }
        } catch (Exception e) {
            logger.error(ApplicationConstants.WRITING_INTO_JSON_FILE_EXCEPTION, e.getMessage());
            Thread.currentThread().interrupt();
        }

        return inputJsonPath;
    }

    public static boolean isPrCommentValueSet(Map<String, Object> scanParameters) {
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY), true)) {
            return true;
        } else if (scanParameters.containsKey(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY), true)) {
            return true;
        } else if (scanParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY), true)) {
            return true;
        }
        return false;
    }

    public static boolean isFixPrValueSet(Map<String, Object> scanParameters) {
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY), true)) {
            return true;
        }
        return false;
    }

    public void removeTemporaryInputJson(List<String> commandLineArgs) {
        for (String arg : commandLineArgs) {
            if (arg.endsWith(".json")) {
                Utility.removeFile(arg, workspace, listener);
            }
        }
    }
}
