package io.jenkins.plugins.security.scan.extension.pipeline;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SecurityScanStepTest {

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
