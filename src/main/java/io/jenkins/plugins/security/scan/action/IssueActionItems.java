package io.jenkins.plugins.security.scan.action;

import hudson.FilePath;
import hudson.model.Action;

public class IssueActionItems implements Action {
    private final String product;
    private final String productUrl;
    private final FilePath filePath;
    private final boolean isPrEvent;

    public IssueActionItems(String product, String productUrl, FilePath filePath, boolean isPrEvent) {
        this.product = product;
        this.productUrl = productUrl;
        this.filePath = filePath;
        this.isPrEvent = isPrEvent;
    }

    public String getProduct() {
        return product;
    }

    public FilePath getFilePath() {
        return filePath;
    }

    public String getProductUrl() {
        return productUrl;
    }

    public boolean isPrEvent() {
        return isPrEvent;
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
