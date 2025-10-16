package io.jenkins.plugins.security.scan.service.bridge;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.File;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BridgeDownloadParameterServiceTest {
    private BridgeDownloadParametersService bridgeDownloadParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private FilePath workspace;
    private final Map<String, Object> scanParameters = new HashMap<>();

    @BeforeEach
    void setUp() {
        workspace = new FilePath(new File(getHomeDirectory()));
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        bridgeDownloadParametersService = new BridgeDownloadParametersService(workspace, listenerMock);
    }

    @Test
    void performBridgeDownloadParameterValidationSuccessTest() throws PluginExceptionHandler {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);
        bridgeDownloadParameters.setBridgeDownloadUrl("https://fake.url.com");
        bridgeDownloadParameters.setBridgeDownloadVersion("1.2.3");

        assertTrue(bridgeDownloadParametersService.performBridgeDownloadParameterValidation(bridgeDownloadParameters));
    }

    @Test
    void performBridgeDownloadParameterValidationFailureTest() {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);
        bridgeDownloadParameters.setBridgeDownloadVersion("x.x.x");

        assertThrows(
                PluginExceptionHandler.class,
                () -> bridgeDownloadParametersService.performBridgeDownloadParameterValidation(
                        bridgeDownloadParameters));
    }

    @Test
    void isValidUrlTest() {
        String validUrl = "https://fake.url.com";
        assertTrue(bridgeDownloadParametersService.isValidUrl(validUrl));

        String ip = "https://102.118.100.102/";
        assertTrue(bridgeDownloadParametersService.isValidUrl(ip));

        String emptyUrl = "";
        assertFalse(bridgeDownloadParametersService.isValidUrl(emptyUrl));

        String invalidUrl = "invalid url";
        assertFalse(bridgeDownloadParametersService.isValidUrl(invalidUrl));
    }

    @Test
    void isValidVersionTest() {
        // Test numeric versions (backward compatibility)
        String validVersion = "1.2.3";
        assertTrue(bridgeDownloadParametersService.isValidVersion(validVersion));
        assertTrue(bridgeDownloadParametersService.isValidVersion("latest"));

        // Test alphanumeric versions (new support)
        assertTrue(bridgeDownloadParametersService.isValidVersion("3.7.1rc1"));
        assertTrue(bridgeDownloadParametersService.isValidVersion("3.8.0beta2"));
        assertTrue(bridgeDownloadParametersService.isValidVersion("4.0.0alpha1"));
        assertTrue(bridgeDownloadParametersService.isValidVersion("3.7.2snapshot"));
        assertTrue(bridgeDownloadParametersService.isValidVersion("2.5.0m1"));

        // Test invalid versions
        String invalidVersion = "x.x.x";
        assertFalse(bridgeDownloadParametersService.isValidVersion(invalidVersion));
        assertFalse(bridgeDownloadParametersService.isValidVersion("invalid"));
        assertFalse(bridgeDownloadParametersService.isValidVersion(""));
    }

    @Test
    void isValidInstallationPathTest() {
        String os = System.getProperty("os.name").toLowerCase();
        String userHome = System.getProperty("user.home");

        String validPath = null;
        String invalidPath = null;
        if (os.contains("win")) {
            validPath = String.join("\\", userHome, ApplicationConstants.DEFAULT_DIRECTORY_NAME);
            invalidPath = String.join("\\", "\\path\\absent", ApplicationConstants.DEFAULT_DIRECTORY_NAME);
        } else if (os.contains("nix") || os.contains("nux") || os.contains("mac")) {
            validPath = String.join("/", userHome, ApplicationConstants.DEFAULT_DIRECTORY_NAME);
            invalidPath = String.join("/", "/path/absent", ApplicationConstants.DEFAULT_DIRECTORY_NAME);
        }

        assertTrue(bridgeDownloadParametersService.isValidInstallationPath(validPath));
        assertFalse(bridgeDownloadParametersService.isValidInstallationPath(invalidPath));
    }

    @Test
    void getBridgeDownloadParamsTest() {
        Map<String, Object> scanParams = new HashMap<>();
        scanParams.put(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION, "3.0.0");
        scanParams.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/path/to/bridge");
        scanParams.put(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL, "https://fake.url.com");

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParams, bridgeDownloadParameters);

        assertEquals("https://fake.url.com", result.getBridgeDownloadUrl());
        assertEquals("/path/to/bridge", result.getBridgeInstallationPath());
    }

    @Test
    void getBridgeDownloadParamsWithAirgapEnabledAndVersionTest() {
        Map<String, Object> scanParams = new HashMap<>();
        scanParams.put(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION, "3.0.0");
        scanParams.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/path/to/bridge");
        scanParams.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParams, bridgeDownloadParameters);

        assertFalse(result.getBridgeDownloadUrl().contains(".zip"));
        assertEquals("/path/to/bridge", result.getBridgeInstallationPath());
    }

    @Test
    void getBridgeDownloadParamsForAirgapTest() {
        Map<String, Object> scanParams = new HashMap<>();
        scanParams.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/path/to/bridge");
        scanParams.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParams, bridgeDownloadParameters);

        assertFalse(result.getBridgeDownloadUrl().contains(".zip"));
        assertEquals("/path/to/bridge", result.getBridgeInstallationPath());
    }

    @Test
    void getBridgeDownloadParamsForAirgapWithURLTest() {
        Map<String, Object> scanParams = new HashMap<>();
        scanParams.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);
        scanParams.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/path/to/bridge");
        scanParams.put(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL, "https://bridge.fake.url.com/bridge-cli.zip");

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParams, bridgeDownloadParameters);

        assertTrue(result.getBridgeDownloadUrl().contains(".zip"));
        assertEquals("/path/to/bridge", result.getBridgeInstallationPath());
    }

    @Test
    void getBridgeDownloadParamsNullTest() {
        Map<String, Object> scanParamsNull = new HashMap<>();

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParamsNull, bridgeDownloadParameters);

        assertNotNull(result);
        assertNotNull(result.getBridgeDownloadUrl());
        assertNotNull(result.getBridgeDownloadVersion());
        assertNotNull(result.getBridgeInstallationPath());
    }

    @Test
    void getPlatformTest() {
        String osName = System.getProperty("os.name").toLowerCase();
        String osArch = System.getProperty("os.arch").toLowerCase();
        String platform = bridgeDownloadParametersService.getPlatform(null);

        assertNotNull(platform);

        boolean isWindows = osName.contains("win");
        boolean isMac = osName.contains("mac");
        boolean isLinux = osName.contains("linux");
        boolean isArm = osArch.startsWith("arm") || osArch.startsWith("aarch");

        if (isWindows) {
            assertEquals(ApplicationConstants.PLATFORM_WINDOWS, platform);
        } else if (isMac) {
            assertEquals(
                    isArm ? ApplicationConstants.PLATFORM_MAC_ARM : ApplicationConstants.PLATFORM_MACOSX, platform);
        } else if (isLinux) {
            assertEquals(
                    isArm ? ApplicationConstants.PLATFORM_LINUX_ARM : ApplicationConstants.PLATFORM_LINUX, platform);
        } else {
            assertEquals(ApplicationConstants.PLATFORM_LINUX, platform);
        }
    }

    @Test
    public void isVersionCompatibleForMacARMTest() {
        assertTrue(Utility.isVersionCompatible(
                "2.1.0", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(Utility.isVersionCompatible(
                "2.2.38", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(Utility.isVersionCompatible(
                "2.0.0", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(Utility.isVersionCompatible(
                "1.2.12", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
    }

    @Test
    public void isVersionCompatibleForLinuxARMTest() {
        assertTrue(Utility.isVersionCompatible(
                "3.5.1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(Utility.isVersionCompatible(
                "3.5.38", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(Utility.isVersionCompatible(
                "2.0.0", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(Utility.isVersionCompatible(
                "1.2.12", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
    }

    @Test
    public void isVersionCompatibleForARMWithAlphanumericVersionsTest() {
        // Test alphanumeric versions - should work with numeric comparison
        assertTrue(Utility.isVersionCompatible(
                "3.7.1rc1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(Utility.isVersionCompatible(
                "4.0.0beta2", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(Utility.isVersionCompatible(
                "3.5.2alpha1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));

        // Test alphanumeric versions below threshold
        assertFalse(Utility.isVersionCompatible(
                "2.1.0rc1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(Utility.isVersionCompatible(
                "3.4.0beta1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));

        // Test "latest" always returns true
        assertTrue(Utility.isVersionCompatible(
                "latest", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
    }

    @Test
    public void performBridgeDownloadParameterValidationWithAlphanumericVersionTest() throws PluginExceptionHandler {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);
        bridgeDownloadParameters.setBridgeDownloadUrl("https://fake.url.com");
        bridgeDownloadParameters.setBridgeDownloadVersion("3.7.1rc1");

        assertTrue(bridgeDownloadParametersService.performBridgeDownloadParameterValidation(bridgeDownloadParameters));
    }

    public String getHomeDirectory() {
        return System.getProperty("user.home");
    }
}
