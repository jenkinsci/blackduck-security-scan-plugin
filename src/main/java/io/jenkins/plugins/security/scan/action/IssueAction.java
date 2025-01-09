package io.jenkins.plugins.security.scan.action;

import hudson.model.Action;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import java.util.HashMap;
import java.util.Map;

public class IssueAction implements Action {
    private final String product;
    private final int defectCount;
    private final String issueViewUrl;

    private static final Map<String, String> PRODUCT_NAME_MAP;

    static {
        PRODUCT_NAME_MAP = new HashMap<>();
        PRODUCT_NAME_MAP.put("polaris", "Polaris");
        PRODUCT_NAME_MAP.put("srm", "SRM");
    }

    public IssueAction(final String product, final int defectCount, final String issueViewUrl) {
        this.product = product;
        this.defectCount = defectCount;
        this.issueViewUrl = issueViewUrl;
    }

    @Override
    public String getIconFileName() {
        return ApplicationConstants.BLACK_DUCK_LOGO_FILE_NAME;
    }

    @Override
    public String getDisplayName() {
        return String.format("See issues in %s (%d found)", getDisplayNameForProduct(product), defectCount);
    }

    @Override
    public String getUrlName() {
        return issueViewUrl;
    }

    private String getDisplayNameForProduct(String product) {
        return PRODUCT_NAME_MAP.getOrDefault(product.toLowerCase(), product);
    }
}
