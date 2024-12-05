package io.jenkins.plugins.security.scan.action;

import hudson.FilePath;
import hudson.model.Action;

public class IssueActionItems implements Action {
    private final String product;
    private final FilePath filePath;

    public IssueActionItems(String product, FilePath filePath) {
        this.product = product;
        this.filePath = filePath;
    }

    public String getProduct() {
        return product;
    }

    public FilePath getFilePath() {
        return filePath;
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return null;
    }
}
