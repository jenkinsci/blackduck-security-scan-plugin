package io.jenkins.plugins.security.scan.service.scan;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.scan.blackducksca.BlackDuckSCAParametersService;
import io.jenkins.plugins.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.security.scan.service.scan.polaris.PolarisParametersService;
import io.jenkins.plugins.security.scan.service.scan.srm.SRMParametersService;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ScanParametersService {
    private final TaskListener listener;

    public ScanParametersService(TaskListener listener) {
        this.listener = listener;
    }

    public boolean performScanParameterValidation(Map<String, Object> scanParameters, EnvVars envVars)
            throws PluginExceptionHandler {
        Set<String> securityProducts = getSecurityProducts(scanParameters);

        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())
                || securityProducts.contains(SecurityProduct.BLACKDUCKSCA.name())) {
            BlackDuckSCAParametersService blackDuckSCAParametersService = new BlackDuckSCAParametersService(listener, envVars);
            if (!blackDuckSCAParametersService.isValidBlackDuckParameters(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_BLACKDUCKSCA_PARAMETERS);
            }
        }
        if (securityProducts.contains(SecurityProduct.COVERITY.name())) {
            CoverityParametersService coverityParametersService = new CoverityParametersService(listener, envVars);
            if (!coverityParametersService.hasAllMandatoryCoverityParams(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_COVERITY_PARAMETERS);
            }
        }
        if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            PolarisParametersService polarisParametersService = new PolarisParametersService(listener, envVars);
            if (!polarisParametersService.hasAllMandatoryCoverityParams(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_POLARIS_PARAMETERS);
            }
        }
        if (securityProducts.contains(SecurityProduct.SRM.name())) {
            SRMParametersService srmParametersService = new SRMParametersService(listener, envVars);
            if (!srmParametersService.hasAllMandatorySrmParams(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_SRM_PARAMETERS);
            }
        }

        return true;
    }

    public Set<String> getSecurityProducts(Map<String, Object> scanParameters) {
        String securityPlatform = (String) scanParameters.get(ApplicationConstants.PRODUCT_KEY);

        return Arrays.stream(securityPlatform.split(","))
                .map(String::trim)
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
    }
}
