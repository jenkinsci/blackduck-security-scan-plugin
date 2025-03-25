package io.jenkins.plugins.security.scan.extension.global;

import com.fasterxml.jackson.databind.JsonNode;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.listeners.RunListener;
import io.jenkins.plugins.security.scan.action.IssueAction;
import io.jenkins.plugins.security.scan.action.IssueActionItems;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.IssueCalculator;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import java.io.File;
import java.io.IOException;

@Extension
public class SecurityScanRunListener extends RunListener<Run<?, ?>> {
    private LoggerWrapper logger;

    @Override
    public void onCompleted(Run<?, ?> run, TaskListener listener) {
        this.logger = new LoggerWrapper(listener);

        IssueActionItems issueActionItems = run.getAction(IssueActionItems.class);
        String product = getProduct(issueActionItems);

        if (product.equals(SecurityProduct.POLARIS.name())
                || product.equals(SecurityProduct.SRM.name())
                || product.equals(SecurityProduct.BLACKDUCKSCA.name())
                || product.equals(SecurityProduct.COVERITY.name())) {
            processScanInfo(run, issueActionItems, product);
        }
    }

    private String getProduct(IssueActionItems issueActionItems) {
        return (issueActionItems != null) ? issueActionItems.getProduct() : ApplicationConstants.NOT_AVAILABLE;
    }

    private void processScanInfo(Run<?, ?> run, IssueActionItems issueActionItems, String product) {
        try {
            FilePath filePath = (issueActionItems != null) ? issueActionItems.getFilePath() : null;
            if (filePath == null || !filePath.exists()) {
                logger.info(ApplicationConstants.SCAN_INFO_FILE_NOT_FOUND);
                return;
            }

            JsonNode rootNode = Utility.parseJsonFile(new File(filePath.getRemote()));

            IssueCalculator issueCalculator = new IssueCalculator();
            String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product.toLowerCase());
            int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product.toLowerCase());

            if (totalIssues != -1 && !issueActionItems.isPrEvent()) {
                run.addAction(new IssueAction(
                        product.toLowerCase(),
                        totalIssues,
                        Utility.isStringNullOrBlank(issuesUrl) ? issueActionItems.getProductUrl() : issuesUrl));
            } else {
                logger.info(ApplicationConstants.SCAN_INFO_ISSUE_COUNT_NOT_FOUND);
            }
        } catch (IOException | InterruptedException | RuntimeException e) {
            logger.info(ApplicationConstants.EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE, e.getMessage());
            Thread.currentThread().interrupt();
        }
    }
}
