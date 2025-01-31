package io.jenkins.plugins.security.scan.action;

import hudson.FilePath;
import hudson.model.Action;

public class IssueActionItems implements Action {
    private final String product;
    private final String productUrl;
    private final FilePath filePath;

    public IssueActionItems(String product, String productUrl, FilePath filePath) {
        this.product = product;
        this.productUrl = productUrl;
        this.filePath = filePath;
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
