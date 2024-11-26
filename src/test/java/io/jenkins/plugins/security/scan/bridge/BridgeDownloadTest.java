package io.jenkins.plugins.security.scan.bridge;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.File;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;

public class BridgeDownloadTest {
    private TaskListener listenerMock;
    private FilePath workspace;
    private EnvVars envVarsMock;

    @BeforeEach
    public void setUp() {
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        envVarsMock = Mockito.mock(EnvVars.class);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    public void downloadBridgeCLITest() throws Exception {
        BridgeDownload bridgeDownload = new BridgeDownload(workspace, listenerMock, envVarsMock);

        String validBridgeDownloadUrl =
                String.join("/", ApplicationConstants.BRIDGE_ARTIFACTORY_URL, "latest", "versions.txt");
        String invalidBridgeDownloadUrl = "https://bridge.invalid.url";

        FilePath validBridgeDownloadPath =
                bridgeDownload.downloadBridgeCLI(validBridgeDownloadUrl, workspace.getRemote());

        assertTrue(Files.exists(Paths.get(validBridgeDownloadPath.getRemote())));
        assertThrows(
                PluginExceptionHandler.class,
                () -> bridgeDownload.downloadBridgeCLI(invalidBridgeDownloadUrl, workspace.getRemote()));

        Utility.removeFile(validBridgeDownloadPath.getRemote(), workspace, listenerMock);
    }

    @Test
    public void getHttpStatusCodeTest() {
        String bridgeDownloadUrl = String.join(
                "/", ApplicationConstants.BRIDGE_ARTIFACTORY_URL, "latest", "bridge-cli-bundle-linux64.zip");
        String invalidDownloadUrl = "https://invalid.bridge-download.url";

        BridgeDownload bridgeDownload = new BridgeDownload(workspace, listenerMock, envVarsMock);

        assertEquals(200, bridgeDownload.getHttpStatusCode(bridgeDownloadUrl));
        assertEquals(-1, bridgeDownload.getHttpStatusCode(invalidDownloadUrl));
    }

    @Test
    public void terminateRetryTest() {
        BridgeDownload bridgeDownload = new BridgeDownload(workspace, listenerMock, envVarsMock);

        assertTrue(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_UNAUTHORIZED));
        assertTrue(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_FORBIDDEN));
        assertTrue(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_OK));
        assertTrue(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_CREATED));
        assertTrue(bridgeDownload.terminateRetry(416));

        assertFalse(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_NOT_FOUND));
        assertFalse(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_BAD_REQUEST));
        assertFalse(bridgeDownload.terminateRetry(HttpURLConnection.HTTP_INTERNAL_ERROR));
    }

    @Test
    public void checkIfBridgeUrlExistsTest() {
        String bridgeDownloadUrl = String.join(
                "/", ApplicationConstants.BRIDGE_ARTIFACTORY_URL, "latest", "bridge-cli-bundle-linux64.zip");
        String invalidUrl = "https://invalid.bridge-download.url";

        BridgeDownload bridgeDownload = new BridgeDownload(workspace, listenerMock, envVarsMock);

        assertTrue(bridgeDownload.checkIfBridgeUrlExists(bridgeDownloadUrl));
        assertFalse(bridgeDownload.checkIfBridgeUrlExists(invalidUrl));
        assertFalse(bridgeDownload.checkIfBridgeUrlExists(null));
    }
}
