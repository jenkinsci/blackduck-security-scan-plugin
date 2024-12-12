package io.jenkins.plugins.security.scan.action;

import hudson.model.Action;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;

public class IssueAction implements Action {
    private final String product;
    private final int defectCount;
    private final String issueViewUrl;

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
        return String.format("See issues in %s (%d found)", product, defectCount);
    }

    @Override
    public String getUrlName() {
        return issueViewUrl;
    }
}
