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
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import java.io.File;

@Extension
public class SecurityScanRunListener extends RunListener<Run<?, ?>> {
    private LoggerWrapper logger;

    @Override
    public void onCompleted(Run<?, ?> run, TaskListener listener) {
        this.logger = new LoggerWrapper(listener);

        IssueActionItems issueActionItems = run.getAction(IssueActionItems.class);
        String product = issueActionItems != null ? issueActionItems.getProduct() : ApplicationConstants.NOT_AVAILABLE;

        if (product.equals(SecurityProduct.POLARIS.name())
                || product.equals(SecurityProduct.SRM.name())
                || product.equals(SecurityProduct.BLACKDUCKSCA.name())
                || product.equals(SecurityProduct.COVERITY.name())
                || product.equals(SecurityProduct.SRM.name())) {
            try {
                FilePath filePath = issueActionItems != null ? issueActionItems.getFilePath() : null;

                if (filePath == null || !filePath.exists()) {
                    logger.error(ApplicationConstants.SCAN_INFO_FILE_NOT_FOUND);
                }

                File localFile = new File(filePath.getRemote());
                JsonNode rootNode = Utility.parseJsonFile(localFile);
                String issuesUrl = Utility.getIssuesUrl(rootNode, product.toLowerCase());
                int totalIssues = Utility.calculateTotalIssues(rootNode, product.toLowerCase());

                run.addAction(new IssueAction(
                        product.toLowerCase(),
                        totalIssues,
                        Utility.isStringNullOrBlank(issuesUrl) ? issueActionItems.getProductUrl() : issuesUrl));
            } catch (RuntimeException e) {
                logger.error(ApplicationConstants.EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE);
            } catch (Exception e) {
                logger.error(ApplicationConstants.EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE);
            }
        }
    }
}
