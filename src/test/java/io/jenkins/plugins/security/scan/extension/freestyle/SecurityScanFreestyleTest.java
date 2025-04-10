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

        EnvVars envVars = new EnvVars();
        envVars.put("ENV_VAR", "expandedValue");

        securityScanFreestyle.handleScanParametersEnvVarsResolution(scanparametersMap, envVars);

        assertEquals("value1", scanparametersMap.get("key1"));
        assertEquals("expandedValue", scanparametersMap.get("key2"));
        assertEquals(123, scanparametersMap.get("key3"));
    }
}
