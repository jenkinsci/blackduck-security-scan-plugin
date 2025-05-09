package io.jenkins.plugins.security.scan.extension.freestyle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class SecurityScanFreestyleTest {
    private SecurityScanFreestyle securityScanFreestyle;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);

    @BeforeEach
    void setUp() {
        securityScanFreestyle = new SecurityScanFreestyle();
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void testConstructorInitialization() {
        assertNull(securityScanFreestyle.getProduct());
        assertNull(securityScanFreestyle.getBlackducksca_url());
        assertNull(securityScanFreestyle.getBlackducksca_token());
    }

    @Test
    void testSettersAndGetters() {
        securityScanFreestyle.setProduct(SecurityProduct.BLACKDUCKSCA.name().toLowerCase());
        securityScanFreestyle.setBlackducksca_url("https://fake.blackduck.url");
        securityScanFreestyle.setBlackducksca_token("fake-token");

        assertEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase(), securityScanFreestyle.getProduct());
        assertEquals("https://fake.blackduck.url", securityScanFreestyle.getBlackducksca_url());
        assertEquals("fake-token", securityScanFreestyle.getBlackducksca_token());
    }

    @Test
    void testReplaceAllExpandsEnvVars() {
        Map<String, Object> scanparametersMap = new HashMap<>();
        scanparametersMap.put("key1", "value1");
        scanparametersMap.put("key2", "${ENV_VAR}");
        scanparametersMap.put("key3", 123);
        scanparametersMap.put("key4", "${NON_ENV_VAR}");

        EnvVars envVars = new EnvVars();
        envVars.put("ENV_VAR", "expandedValue");

        Map<String, Object> scanParamMapExp =
                securityScanFreestyle.handleScanParametersEnvVarsResolution(scanparametersMap, envVars);

        assertEquals(scanparametersMap.get("key1"), scanParamMapExp.get("key1"));
        assertEquals(envVars.get("ENV_VAR"), scanParamMapExp.get("key2"));
        assertEquals(scanparametersMap.get("key3"), scanParamMapExp.get("key3"));
        assertEquals(scanparametersMap.get("key4"), scanParamMapExp.get("key4"));
    }
}
