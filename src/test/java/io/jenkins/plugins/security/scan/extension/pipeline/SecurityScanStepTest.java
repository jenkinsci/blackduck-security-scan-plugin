package io.jenkins.plugins.security.scan.extension.pipeline;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class SecurityScanStepTest {
    private ByteArrayOutputStream logOutput;
    private LoggerWrapper logger;
    private EnvVars envVars;
    private SecurityScanStep.Execution execution;

    @BeforeEach
    void setUp() throws Exception {
        logOutput = new ByteArrayOutputStream();
        TaskListener listener = mock(TaskListener.class);
        when(listener.getLogger()).thenReturn(new PrintStream(logOutput));
        envVars = mock(EnvVars.class);
        logger = new LoggerWrapper(listener);

        StepContext context = mock(StepContext.class);
        when(context.get(TaskListener.class)).thenReturn(listener);
        when(context.get(EnvVars.class)).thenReturn(envVars);
        execution = new SecurityScanStep().new Execution(context);
    }

    private Map<String, Object> prCommentParameters() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        return scanParameters;
    }

    @Test
    void verifyRequiredPluginsNonMultibranchJobDoesNothingTest() {
        try (MockedStatic<Utility> utility = Mockito.mockStatic(Utility.class)) {
            utility.when(() -> Utility.jenkinsJobType(envVars)).thenReturn("WorkflowJob");

            assertDoesNotThrow(() -> execution.verifyRequiredPlugins(logger, envVars, prCommentParameters()));
            assertEquals("", logOutput.toString());
        }
    }

    @Test
    void verifyRequiredPluginsScanOnlyWithoutPluginsLogsInfoTest() {
        try (MockedStatic<Utility> utility = Mockito.mockStatic(Utility.class)) {
            utility.when(() -> Utility.jenkinsJobType(envVars))
                    .thenReturn(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME);
            utility.when(Utility::installedBranchSourceDependencies).thenReturn(Collections.emptyMap());

            assertDoesNotThrow(() -> execution.verifyRequiredPlugins(logger, envVars, new HashMap<>()));
            assertTrue(logOutput.toString().contains(ApplicationConstants.NO_BRANCH_SOURCE_PLUGIN_FOUND_INFO));
        }
    }

    @Test
    void verifyRequiredPluginsScanOnlyWithPluginsDoesNotLogTest() {
        try (MockedStatic<Utility> utility = Mockito.mockStatic(Utility.class)) {
            utility.when(() -> Utility.jenkinsJobType(envVars))
                    .thenReturn(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME);
            utility.when(Utility::installedBranchSourceDependencies)
                    .thenReturn(Map.of(ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, true));

            assertDoesNotThrow(() -> execution.verifyRequiredPlugins(logger, envVars, new HashMap<>()));
            assertEquals("", logOutput.toString());
        }
    }

    @Test
    void verifyRequiredPluginsPrCommentWithoutPluginsThrowsTest() {
        try (MockedStatic<Utility> utility = Mockito.mockStatic(Utility.class)) {
            utility.when(() -> Utility.jenkinsJobType(envVars))
                    .thenReturn(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME);
            utility.when(Utility::installedBranchSourceDependencies).thenReturn(Collections.emptyMap());

            PluginExceptionHandler exception = assertThrows(
                    PluginExceptionHandler.class,
                    () -> execution.verifyRequiredPlugins(logger, envVars, prCommentParameters()));

            assertEquals(ErrorCode.REQUIRED_BRANCH_SOURCE_PLUGIN_NOT_INSTALLED, exception.getCode());
            String output = logOutput.toString();
            assertTrue(output.contains(ApplicationConstants.NECESSARY_BRANCH_SOURCE_PLUGIN_IS_NOT_INSTALLED));
            assertFalse(output.contains(ApplicationConstants.NO_BRANCH_SOURCE_PLUGIN_FOUND_INFO));
        }
    }

    @Test
    void branchSourcePluginIsNotRequiredForScanOnly() {
        assertFalse(SecurityScanStep.requiresBranchSourcePlugin(new HashMap<>()));
    }

    @Test
    void branchSourcePluginIsRequiredForPrComment() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);

        assertTrue(SecurityScanStep.requiresBranchSourcePlugin(scanParameters));
    }

    @Test
    void branchSourcePluginIsRequiredForFixPr() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY, true);

        assertTrue(SecurityScanStep.requiresBranchSourcePlugin(scanParameters));
    }
}
