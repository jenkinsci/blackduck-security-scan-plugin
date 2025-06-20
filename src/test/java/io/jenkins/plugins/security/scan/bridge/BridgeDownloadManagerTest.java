package io.jenkins.plugins.security.scan.bridge;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BridgeDownloadManagerTest {
    private BridgeDownloadManager bridgeDownloadManager;
    private FilePath workspace;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final Map<String, Object> scanParameters = new HashMap<>();

    @BeforeEach
    void setup() {
        workspace = new FilePath(new File(getHomeDirectory()));
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        bridgeDownloadManager = new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);
    }

    @Test
    public void getInstalledBridgeVersionTest() {
        String versionFilePath = null;
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            versionFilePath = new File("src\\test\\resources\\versions.txt").getAbsolutePath();

        } else {
            versionFilePath = new File("src/test/resources/versions.txt").getAbsolutePath();
        }

        String installedVersion = bridgeDownloadManager.getBridgeVersionFromVersionFile(versionFilePath);

        assertNotNull(versionFilePath, "version.txt file not found");
        assertEquals("3.0.0", installedVersion);
    }

    @Test
    void isBridgeDownloadRequiredTest() {
        BridgeDownloadParameters bridgeDownloadParameters =
                new BridgeDownloadParameters(workspace, listenerMock, envVarsMock, scanParameters);
        bridgeDownloadParameters.setBridgeDownloadUrl("https://fake.url.com/bridge");
        bridgeDownloadParameters.setBridgeInstallationPath("/path/to/bridge");

        BridgeDownloadManager mockedBridgeDownloadManager = Mockito.mock(BridgeDownloadManager.class);

        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        Mockito.when(mockedBridgeDownloadManager.checkIfBridgeInstalled(anyString()))
                .thenReturn(true);
        boolean isDownloadRequired = bridgeDownloadManager.isBridgeDownloadRequired(bridgeDownloadParameters);

        assertTrue(isDownloadRequired);
    }

    @Test
    public void getDirectoryUrlTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        String downloadUrlWithoutTrailingSlash =
                "https://myown.artifactory.com/release/bridge-cli/0.3.59/bridge-cli-0.3.59-linux64.zip";
        String directoryUrl = "https://myown.artifactory.com/release/bridge-cli/0.3.59";

        assertEquals(directoryUrl, bridgeDownloadManager.getDirectoryUrl(downloadUrlWithoutTrailingSlash));

        String downloadUrlWithTrailingSlash =
                "https://myown.artifactory.com/release/bridge-cli/latest/bridge-cli-linux64.zip/";
        String expectedDirectoryUrl = "https://myown.artifactory.com/release/bridge-cli/latest";

        assertEquals(expectedDirectoryUrl, bridgeDownloadManager.getDirectoryUrl(downloadUrlWithTrailingSlash));
    }

    @Test
    public void versionFileAvailableTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        String directoryUrlWithoutVersionFile =
                "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/3.0.0/";
        String directoryUrlWithVersionFile =
                "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/";

        assertFalse(bridgeDownloadManager.isVersionFileAvailableInArtifactory(directoryUrlWithoutVersionFile));
        assertTrue(bridgeDownloadManager.isVersionFileAvailableInArtifactory(directoryUrlWithVersionFile));
    }

    @Test
    public void extractVersionFromUrlTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        String urlWithVersion = "https://myown.artifactory.com/bridge-cli/0.3.59/bridge-cli-0.3.59-linux64.zip";
        String expectedVersionWithVersion = "0.3.59";

        assertEquals(expectedVersionWithVersion, Utility.extractVersionFromUrl(urlWithVersion));

        String urlWithoutVersion = "https://myown.artifactory.com/bridge-cli/latest/bridge-cli-latest-linux64.zip";
        String expectedVersionWithLatest = "NA";

        assertEquals(expectedVersionWithLatest, Utility.extractVersionFromUrl(urlWithoutVersion));
    }

    @Test
    public void downloadVersionFileTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        String directoryUrl =
                "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest";
        String tempVersionFilePath = bridgeDownloadManager.downloadVersionFileFromArtifactory(directoryUrl);
        FilePath tempVersionFile = new FilePath(new File(tempVersionFilePath));

        assertNotNull(tempVersionFilePath);
        try {
            assertTrue(tempVersionFile.exists());
        } catch (IOException | InterruptedException e) {
            System.out.println("Exception while checking the existence of downloaded version file.");
        }
        Utility.removeFile(tempVersionFilePath, new FilePath(new File(getHomeDirectory())), listenerMock);
    }

    @Test
    void getLatestBridgeVersionFromArtifactoryTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        String urlWithVersion =
                "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/3.0.0/bridge-cli-3.0.0-linux64.zip ";
        String resultWithVersion = bridgeDownloadManager.getLatestBridgeVersionFromArtifactory(urlWithVersion);

        assertEquals("3.0.0", resultWithVersion);

        String urlWithoutVersion =
                "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle/latest/bridge-cli-linux64.zip";
        BridgeDownloadManager mockedBridgeDownloadManager = Mockito.mock(BridgeDownloadManager.class);
        String expectedVersion = "3.0.0";
        Mockito.when(mockedBridgeDownloadManager.getLatestBridgeVersionFromArtifactory(urlWithoutVersion))
                .thenReturn(expectedVersion);

        String resultWithoutVersion =
                mockedBridgeDownloadManager.getLatestBridgeVersionFromArtifactory(urlWithoutVersion);

        assertEquals(expectedVersion, resultWithoutVersion);
    }

    public String getHomeDirectory() {
        return System.getProperty("user.home");
    }
}
