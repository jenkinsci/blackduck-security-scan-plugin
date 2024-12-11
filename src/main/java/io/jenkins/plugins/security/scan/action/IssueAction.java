package io.jenkins.plugins.security.scan.action;

import hudson.model.Action;

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
        return "/plugin/black-duck-security-scan/icons/blackduck.png";
    }

    @Override
    public String getDisplayName() {
        return "See issues in " + product + " (" + defectCount + " found)";
    }

    @Override
    public String getUrlName() {
        return issueViewUrl;
    }
}
