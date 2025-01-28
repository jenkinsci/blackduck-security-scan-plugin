package io.jenkins.plugins.security.scan.service;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.BridgeParams;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.input.blackducksca.Automation;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.coverity.Connect;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.coverity.CoverityProject;
import io.jenkins.plugins.security.scan.input.coverity.Stream;
import io.jenkins.plugins.security.scan.input.polaris.*;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.project.Source;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.security.scan.input.srm.SRM;
import io.jenkins.plugins.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.security.scan.service.scm.github.GithubRepositoryService;
import io.jenkins.plugins.security.scan.service.scm.gitlab.GitlabRepositoryService;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class ToolsParameterServiceTest {
    private Bitbucket bitBucket;
    private ToolsParameterService toolsParameterService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String CLOUD_API_URI = "https://api.github.com";
    private FilePath workspace;
    private final String TOKEN = "MDJDSROSVC56FAKEKEY";

    @BeforeEach
    void setUp() {
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        workspace = new FilePath(new File(getHomeDirectoryForTest())).child("mock-workspace");

        bitBucket = new Bitbucket();
        bitBucket.getProject().getRepository().setName("fake-repo");

        Mockito.doReturn("fake-branch").when(envVarsMock).get(ApplicationConstants.ENV_BRANCH_NAME_KEY);
        Mockito.doReturn("fake-job/branch").when(envVarsMock).get(ApplicationConstants.ENV_JOB_NAME_KEY);
        Mockito.doReturn("0").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        Mockito.doReturn("fake-main").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_TARGET_KEY);
        Mockito.doReturn("fake-pr-branch").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_BRANCH_KEY);

        toolsParameterService = new ToolsParameterService(listenerMock, envVarsMock, workspace);
    }

    @Test
    void createBlackDuckInputJsonTest() {
        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        blackDuckSCA.setUrl("https://fake.blackduck.url");
        blackDuckSCA.setToken(TOKEN);

        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, blackDuckSCA, bitBucket, ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    void bitbucket_blackDuckInputJson_withoutPrCommentTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        blackDuckSCA.setUrl("https://fake.blackduck.url");
        blackDuckSCA.setToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "test-branch", "abc", "fake-user");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"blackducksca\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"}}}";

            String inputJsonPathForNonFixPr = toolsParameterService.prepareBridgeInputJson(
                    scanParameters,
                    blackDuckSCA,
                    bitbucketObject,
                    ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void bitbucket_blackDuckInputJson_withPrCommentTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        blackDuckSCA.setUrl("https://fake.blackduck.url");
        blackDuckSCA.setToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "test-branch", "abc", "fake-user");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"blackducksca\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"},\"bitbucket\":{\"api\":{\"user\":{\"name\":\"fake-user\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"pull\":{\"number\":12},\"branch\":{\"name\":\"test-branch\"},\"name\":\"test\"}},\"workspace\":{\"id\":\"abc\"}}}}";

            String inputJsonPathForNonFixPr = toolsParameterService.prepareBridgeInputJson(
                    scanParameters,
                    blackDuckSCA,
                    bitbucketObject,
                    ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void bitbucket_blackDuckInputJson_withFixPrTest() {
        ObjectMapper objectMapper = new ObjectMapper();
        Mockito.doReturn(null).when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        blackDuckSCA.setUrl("https://fake.blackduck.url");
        blackDuckSCA.setToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY, true);

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, null, "test", "test-branch", "abc", "fake-user");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"blackducksca\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"},\"bitbucket\":{\"api\":{\"user\":{\"name\":\"fake-user\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"branch\":{\"name\":\"test-branch\"},\"name\":\"test\"}},\"workspace\":{\"id\":\"abc\"}}}}";

            String inputJsonPathForFixPr = toolsParameterService.prepareBridgeInputJson(
                    scanParameters,
                    blackDuckSCA,
                    bitbucketObject,
                    ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void createPolarisInputJsonTest() {
        Polaris polaris = new Polaris();
        polaris.setServerUrl("https://fake.polaris.url");
        polaris.setAccessToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.POLARIS.name());
        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, polaris, bitBucket, ApplicationConstants.POLARIS_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.POLARIS_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    void bitbucket_polarisInputJson_withoutPrCommentTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        Polaris polaris = new Polaris();
        polaris.setServerUrl("https://fake.polaris.url");
        polaris.setAccessToken(TOKEN);
        polaris.setApplicationName(new ApplicationName());
        polaris.getApplicationName().setName("test");
        polaris.setPolarisProject(new PolarisProject());
        polaris.getPolarisProject().setName("test");
        polaris.setAssessmentTypes(new AssessmentTypes());
        polaris.getAssessmentTypes().setTypes(List.of("SCA", "SAST"));
        polaris.setBranch(new Branch());
        polaris.getBranch().setName("fake-pr-branch");

        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "test-branch", "abc", "fake-username");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"polaris\":{\"accesstoken\":\"MDJDSROSVC56FAKEKEY\",\"application\":{\"name\":\"test\"},\"project\":{\"name\":\"test\"},\"assessment\":{\"types\":[\"SCA\",\"SAST\"]},\"serverUrl\":\"https://fake.polaris.url\",\"branch\":{\"name\":\"fake-pr-branch\"}}}}";

            String inputJsonPathForNonFixPr = toolsParameterService.prepareBridgeInputJson(
                    scanParameters, polaris, bitbucketObject, ApplicationConstants.POLARIS_INPUT_JSON_PREFIX, null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void bitbucket_polarisInputJson_withPrCommentTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        Polaris polaris = new Polaris();
        polaris.setServerUrl("https://fake.polaris.url");
        polaris.setAccessToken(TOKEN);
        polaris.setApplicationName(new ApplicationName());
        polaris.getApplicationName().setName("test");
        polaris.setPolarisProject(new PolarisProject());
        polaris.getPolarisProject().setName("test");
        polaris.setAssessmentTypes(new AssessmentTypes());
        polaris.getAssessmentTypes().setTypes(List.of("SCA", "SAST"));
        polaris.setBranch(new Branch());
        polaris.getBranch().setName("fake-pr-branch");

        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.POLARIS.name());
        scanParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "test-branch", "abc", "fake-username");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"polaris\":{\"serverUrl\":\"https://fake.polaris.url\",\"accesstoken\":\"MDJDSROSVC56FAKEKEY\",\"application\":{\"name\":\"test\"},\"project\":{\"name\":\"test\"},\"assessment\":{\"types\":[\"SCA\",\"SAST\"]},\"branch\":{\"name\":\"fake-pr-branch\"}},\"bitbucket\":{\"api\":{\"user\":{\"name\":\"fake-username\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"pull\":{\"number\":12},\"branch\":{\"name\":\"test-branch\"},\"name\":\"test\"}},\"workspace\":{\"id\":\"abc\"}}}}";

            String inputJsonPathForNonFixPr = toolsParameterService.prepareBridgeInputJson(
                    scanParameters, polaris, bitbucketObject, ApplicationConstants.POLARIS_INPUT_JSON_PREFIX, null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void createSrmInputJsonTest() {
        SRM srm = new SRM();
        srm.setUrl("https://fake.srm.url");
        srm.setApikey(TOKEN);
        srm.getAssessmentTypes().setTypes(List.of("SCA"));
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.SRM.name());

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, srm, bitBucket, ApplicationConstants.SRM_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.SRM_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void writeInputJsonToFileTest() {
        String jsonString =
                "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"}}}";

        String jsonPath = toolsParameterService.writeInputJsonToFile(
                jsonString, ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX);
        String fileContent = null;
        try {
            fileContent = new String(Files.readAllBytes(Paths.get(jsonPath)));
        } catch (IOException e) {
            e.printStackTrace();
        }

        assertTrue(
                Files.exists(Path.of(jsonPath)),
                String.format(
                        "%s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(jsonString, fileContent);

        Utility.removeFile(jsonPath, workspace, listenerMock);
    }

    @Test
    public void createCoverityInputJsonTest() {
        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.COVERITY.name());

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, coverity, bitBucket, ApplicationConstants.COVERITY_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void github_coverityInputJsonTest() throws PluginExceptionHandler {
        ObjectMapper objectMapper = new ObjectMapper();
        GithubRepositoryService githubRepositoryService = new GithubRepositoryService(listenerMock);

        Map<String, Object> scanParametersMap = new HashMap<>();
        scanParametersMap.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.COVERITY.name());
        scanParametersMap.put(ApplicationConstants.GITHUB_TOKEN_KEY, TOKEN);
        scanParametersMap.put(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY, true);

        String jsonStringForPrComment = "{\"data\":{\"coverity\":{\"connect\":{\"url\":\"https://fake.coverity.url\","
                + "\"user\":{\"name\":\"fake-user\",\"password\":\"fakeUserPassword\"},"
                + "\"project\":{\"name\":\"fake-repo\"},\"stream\":{\"name\":\"fake-repo-fake-main\"}"
                + "}},"
                + "\"github\":{\"user\":{\"token\":\"MDJDSROSVC56FAKEKEY\"},\"repository\":{\"name\":\"fake-repo\""
                + ",\"owner\":{\"name\":\"fake-owner\"},\"pull\":{\"number\":1},\"branch\":{\"name\":"
                + "\"fake-branch\"}}}}}";

        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");
        coverity.getConnect().setCoverityProject(new CoverityProject());
        coverity.getConnect().getCoverityProject().setName("fake-repo");
        coverity.getConnect().setStream(new Stream());
        coverity.getConnect().getStream().setName("fake-repo-fake-main");

        try {
            Github github = githubRepositoryService.createGithubObject(
                    scanParametersMap, "fake-repo", "fake-owner", 1, "fake-branch", CLOUD_API_URI);
            String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                    scanParametersMap, coverity, github, ApplicationConstants.COVERITY_INPUT_JSON_PREFIX, null);
            Path filePath = Paths.get(inputJsonPath);

            assertTrue(
                    Files.exists(filePath),
                    String.format(
                            "File %s does not exist at the specified path.",
                            ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            String actualJsonString = new String(Files.readAllBytes(filePath));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void gitlab_blackDuckInputJsonTest() throws PluginExceptionHandler {
        GitlabRepositoryService gitlabRepositoryService = new GitlabRepositoryService(listenerMock);
        ObjectMapper objectMapper = new ObjectMapper();

        Map<String, Object> scanParametersMap = new HashMap<>();
        scanParametersMap.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());
        scanParametersMap.put(ApplicationConstants.GITLAB_TOKEN_KEY, TOKEN);
        scanParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);

        BlackDuckSCA blackDuckSCA = new BlackDuckSCA();
        blackDuckSCA.setUrl("https://fake.blackduck.url");
        blackDuckSCA.setToken(TOKEN);
        blackDuckSCA.setAutomation(new Automation());
        blackDuckSCA.getAutomation().setPrComment(true);

        String jsonStringForPrComment =
                "{\"data\":{\"blackducksca\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\",\"automation\":{\"prComment\":true}},\"gitlab\":{\"user\":{\"token\":\"MDJDSROSVC56FAKEKEY\"},\"repository\":{\"branch\":{\"name\":\"fake-gitlab-branch\"},\"pull\":{\"number\":12},\"name\":\"fake-group/fake-gitlab-repo\"}}}}";

        try {
            Gitlab gitlabObject = gitlabRepositoryService.createGitlabObject(
                    scanParametersMap,
                    "fake-group/fake-gitlab-repo",
                    12,
                    "fake-gitlab-branch",
                    "https://gitlab.com/fake-group/fake-gitlab-repo.git");
            String inputJsonPathForGitlabPrComment = toolsParameterService.prepareBridgeInputJson(
                    scanParametersMap,
                    blackDuckSCA,
                    gitlabObject,
                    ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX,
                    null);

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            Path filePath = Paths.get(inputJsonPathForGitlabPrComment);
            String actualJsonString = new String(Files.readAllBytes(Paths.get(inputJsonPathForGitlabPrComment)));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void createDetectInputJsonTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());
        scanParameters.put(ApplicationConstants.DETECT_ARGS_KEY, "args");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_SCAN_FULL_KEY, true);
        scanParameters.put(ApplicationConstants.DETECT_EXECUTION_PATH_KEY, "path/detect");

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, null, null, ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void createNetworkAirGapInputJsonTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());
        scanParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, null, null, ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void createProjectInputJsonTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.POLARIS.name());
        Project project = new Project();
        project.setDirectory("/tmp/dir");
        Source source = new Source();
        source.setPreserveSymLinks(true);
        project.setSource(source);

        String inputJsonPath = toolsParameterService.prepareBridgeInputJson(
                scanParameters, null, null, ApplicationConstants.POLARIS_INPUT_JSON_PREFIX, project);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.POLARIS_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForBlackDuckTest() throws PluginExceptionHandler {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.BLACKDUCK.name());
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, false);
        blackDuckParametersMap.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, true);

        List<String> commandLineArgs = toolsParameterService.getCommandLineArgs(blackDuckParametersMap, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace
                            .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS)
                            .getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.BLACKDUCKSCA_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCKSCA_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.OUT_OPTION);
        assertEquals(commandLineArgs.get(7), BridgeParams.DIAGNOSTICS_OPTION);

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForCoverityTest() throws PluginExceptionHandler {
        Map<String, Object> coverityParameters = new HashMap<>();
        coverityParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.COVERITY.name());
        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, "https://fake.coverity.url");
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, "fake-user");
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, "fakeUserPassword");
        coverityParameters.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, true);

        List<String> commandLineArgs = toolsParameterService.getCommandLineArgs(coverityParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace
                            .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS)
                            .getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.COVERITY_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.DIAGNOSTICS_OPTION);

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForPolarisTest() throws PluginExceptionHandler {
        Map<String, Object> polarisParameters = new HashMap<>();
        polarisParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.POLARIS.name());
        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, "https://fake.polaris.url");
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, "fake-token");
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, "Fake-application-name");
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");

        List<String> commandLineArgs = toolsParameterService.getCommandLineArgs(polarisParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace
                            .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS)
                            .getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.POLARIS_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.POLARIS_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.OUT_OPTION);
        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForSrmTest() throws PluginExceptionHandler {
        Map<String, Object> srmParameters = new HashMap<>();
        srmParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.SRM.name());
        srmParameters.put(ApplicationConstants.SRM_URL_KEY, "https://fake.srm.url");
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, "fake-api-key");
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, "SCA");
        srmParameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, "fake-project-name");
        srmParameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, "fake-project-id");

        List<String> commandLineArgs = toolsParameterService.getCommandLineArgs(srmParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace
                            .child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE_WINDOWS)
                            .getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_CLI_EXECUTABLE).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.SRM_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.SRM_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.OUT_OPTION);
        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void isPrCommentValueSetTest() {
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        assertTrue(ToolsParameterService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY, true);
        assertTrue(ToolsParameterService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        assertTrue(ToolsParameterService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        assertFalse(ToolsParameterService.isPrCommentValueSet(scanParameters));
    }

    @Test
    public void removeTemporaryInputJsonTest() {
        String[] fileNames = {"file1.json", "file2.json"};
        List<String> inputJsonPath = new ArrayList<>();

        for (String fileName : fileNames) {
            Path filePath = Paths.get(getHomeDirectoryForTest(), fileName);
            String jsonContent = "{\"key\": \"value\"}";

            try {
                Files.write(filePath, jsonContent.getBytes());
                inputJsonPath.add(filePath.toString());
            } catch (IOException e) {
                System.err.println("Error creating file: " + filePath);
            }
        }

        toolsParameterService.removeTemporaryInputJson(inputJsonPath);

        for (String path : inputJsonPath) {
            assertFalse(Files.exists(Paths.get(path)));
        }
    }

    public String getHomeDirectoryForTest() {
        return System.getProperty("user.home");
    }

    public String getOSNameForTest() {
        return System.getProperty("os.name").toLowerCase();
    }
}
