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

    @Test
    public void getBridgeVersionFromVersionFileWithAlphanumericVersionTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        // Test alphanumeric version parsing (new format)
        String alphanumericVersionsFileContent = "bridge-cli-bundle: 3.7.1rc1\nother-component: 1.0.0";

        // Create temporary file with alphanumeric version content
        try {
            FilePath tempFile = workspace.createTempFile("versions_alphanumeric", ".txt");
            tempFile.write(alphanumericVersionsFileContent, "UTF-8");

            String alphanumericVersion = bridgeDownloadManager.getBridgeVersionFromVersionFile(tempFile.getRemote());
            assertEquals("3.7.1rc1", alphanumericVersion);

            // Cleanup
            tempFile.delete();
        } catch (IOException | InterruptedException e) {
            fail("Exception occurred during alphanumeric version test: " + e.getMessage());
        }
    }

    @Test
    public void getBridgeVersionFromVersionFileBackwardCompatibilityTest() {
        BridgeDownloadManager bridgeDownloadManager =
                new BridgeDownloadManager(workspace, listenerMock, envVarsMock, scanParameters);

        // Test backward compatibility with numeric versions
        String numericVersionsFileContent = "bridge-cli-bundle: 3.0.0\nother-component: 1.0.0";

        try {
            FilePath tempFile = workspace.createTempFile("versions_numeric", ".txt");
            tempFile.write(numericVersionsFileContent, "UTF-8");

            String numericVersion = bridgeDownloadManager.getBridgeVersionFromVersionFile(tempFile.getRemote());
            assertEquals("3.0.0", numericVersion);

            // Cleanup
            tempFile.delete();
        } catch (IOException | InterruptedException e) {
            fail("Exception occurred during backward compatibility test: " + e.getMessage());
        }
    }

    @Test
    public void extractVersionFromUrlWithAlphanumericVersionTest() {
        // Test URL with alphanumeric version
        String urlWithAlphanumericVersion =
                "https://artifactory.tools.duckutil.net/artifactory/clops-local/integrations/bridge/binaries/bridge-cli-bundle/3.7.1rc1/bridge-cli-bundle-3.7.1rc1-win64.zip";
        String extractedAlphanumericVersion = Utility.extractVersionFromUrl(urlWithAlphanumericVersion);
        assertEquals("3.7.1rc1", extractedAlphanumericVersion);
    }

    @Test
    public void extractVersionFromUrlBackwardCompatibilityTest() {
        // Test backward compatibility with numeric versions
        String urlWithNumericVersion = "https://repo.blackduck.com/bridge-cli/3.0.0/bridge-cli-3.0.0-linux64.zip";
        String extractedNumericVersion = Utility.extractVersionFromUrl(urlWithNumericVersion);
        assertEquals("3.0.0", extractedNumericVersion);
    }

    @Test
    public void extractVersionFromUrlVariousAlphanumericFormatsTest() {
        // Test various alphanumeric formats
        String urlWithBeta = "https://example.com/bridge/3.7.1beta2/bridge-cli.zip";
        assertEquals("3.7.1beta2", Utility.extractVersionFromUrl(urlWithBeta));

        String urlWithAlpha = "https://example.com/bridge/3.8.0alpha1/bridge-cli.zip";
        assertEquals("3.8.0alpha1", Utility.extractVersionFromUrl(urlWithAlpha));

        String urlWithRc = "https://example.com/bridge/4.0.0rc10/bridge-cli.zip";
        assertEquals("4.0.0rc10", Utility.extractVersionFromUrl(urlWithRc));

        String urlWithSnapshot = "https://example.com/bridge/3.7.2snapshot/bridge-cli.zip";
        assertEquals("3.7.2snapshot", Utility.extractVersionFromUrl(urlWithSnapshot));
    }

    public String getHomeDirectory() {
        return System.getProperty("user.home");
    }
}
