package io.jenkins.plugins.security.scan.service.bridge;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
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

    @BeforeEach
    void setUp() {
        workspace = new FilePath(new File(getHomeDirectory()));
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        bridgeDownloadParametersService = new BridgeDownloadParametersService(workspace, listenerMock);
    }

    @Test
    void performBridgeDownloadParameterValidationSuccessTest() throws PluginExceptionHandler {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);
        bridgeDownloadParameters.setBridgeDownloadUrl("https://fake.url.com");
        bridgeDownloadParameters.setBridgeDownloadVersion("1.2.3");

        assertTrue(bridgeDownloadParametersService.performBridgeDownloadParameterValidation(bridgeDownloadParameters));
    }

    @Test
    void performBridgeDownloadParameterValidationFailureTest() {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);
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
        String validVersion = "1.2.3";
        assertTrue(bridgeDownloadParametersService.isValidVersion(validVersion));
        assertTrue(bridgeDownloadParametersService.isValidVersion("latest"));

        String invalidVersion = "x.x.x";
        assertFalse(bridgeDownloadParametersService.isValidVersion(invalidVersion));
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
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);

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
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);

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
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);

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
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);

        BridgeDownloadParameters result =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParams, bridgeDownloadParameters);

        assertTrue(result.getBridgeDownloadUrl().contains(".zip"));
        assertEquals("/path/to/bridge", result.getBridgeInstallationPath());
    }

    @Test
    void getBridgeDownloadParamsNullTest() {
        Map<String, Object> scanParamsNull = new HashMap<>();

        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock);

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
        assertTrue(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "2.1.0", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "2.2.38", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "2.0.0", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "1.2.12", ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION));
    }

    @Test
    public void isVersionCompatibleForLinuxARMTest() {
        assertTrue(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "3.5.1", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertTrue(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "3.5.38", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "2.0.0", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
        assertFalse(bridgeDownloadParametersService.isVersionCompatibleForARMChips(
                "1.2.12", ApplicationConstants.LINUX_ARM_COMPATIBLE_BRIDGE_VERSION));
    }

    public String getHomeDirectory() {
        return System.getProperty("user.home");
    }
}
