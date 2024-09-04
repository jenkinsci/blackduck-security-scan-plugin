package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.detect.Detect;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DetectParametersServiceTest {
    private DetectParametersService detectParametersService;

    @BeforeEach
    void setUp() {
        detectParametersService = new DetectParametersService();
    }

    @Test
    public void testPrepareDetectObject_forNoDetectInputs() {
        Map<String, Object> detectParametersMap = new HashMap<>();

        Detect detect = detectParametersService.prepareDetectObject(detectParametersMap);

        assertNull(detect.getScan());
        assertNull(detect.getInstall());
        assertNull(detect.getArgs());
    }

    @Test
    public void testPrepareDetectObject() {
        Map<String, Object> detectParametersMap = new HashMap<>();

        detectParametersMap.put(ApplicationConstants.DETECT_SCAN_FULL_KEY, true);
        detectParametersMap.put(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY, "/user/tmp/detect");
        detectParametersMap.put(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY, "https://fake.detect.url");

        Detect detect = detectParametersService.prepareDetectObject(detectParametersMap);

        assertNotNull(detect);
        assertEquals(detect.getScan().getFull(), true);
        assertEquals(detect.getInstall().getDirectory(), "/user/tmp/detect");
        assertEquals(detect.getDownload().getUrl(), "https://fake.detect.url");
        assertNull(detect.getArgs());
        assertNull(detect.getConfig());
        assertNull(detect.getSearch());
    }

    @Test
    public void testPrepareDetectObject_forArbitaryInputs() {
        Map<String, Object> detectParametersMap = new HashMap<>();

        detectParametersMap.put(ApplicationConstants.DETECT_ARGS_KEY, "--detect.diagnostic=true");
        detectParametersMap.put(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY, 2);
        detectParametersMap.put(ApplicationConstants.DETECT_CONFIG_PATH_KEY, "DIR/CONFIG/application.properties");

        Detect detect = detectParametersService.prepareDetectObject(detectParametersMap);

        assertNotNull(detect);
        assertEquals(detect.getArgs(), "--detect.diagnostic=true");
        assertEquals(detect.getSearch().getDepth(), 2);
        assertEquals(detect.getConfig().getPath(), "DIR/CONFIG/application.properties");
        assertNull(detect.getScan());
        assertNull(detect.getInstall());
        assertNull(detect.getDownload());
    }

}
