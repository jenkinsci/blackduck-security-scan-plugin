package io.jenkins.plugins.security.scan.global;

import com.fasterxml.jackson.databind.JsonNode;
import io.jenkins.plugins.security.scan.global.enums.AssessmentType;
import io.jenkins.plugins.security.scan.global.enums.IssueSeverities;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;

public class IssueCalculator {

    private final String DATA_PROPERTY = "data";
    private final String PROJECT_PROPERTY = "project";
    private final String ISSUES_PROPERTY = "issues";
    private final String URL_PROPERTY = "url";
    private final String TEST_PROPERTY = "test";
    private final String ANALYSIS_PROPERTY = "analysis";
    private final String PROJECT_BOM_URL_PROPERTY = "projectBomUrl";
    private final String RESULT_URL_PROPERTY = "resultURL";
    private final String POLICY_PROPERTY = "policy";
    private final String STATUS_PROPERTY = "status";
    private final String CONNECT_PROPERTY = "connect";
    private final String ISSUE_COUNT_PROPERTY = "issueCount";

    public String getIssuesUrl(JsonNode rootNode, String product) {
        JsonNode productNode = rootNode.path(DATA_PROPERTY).path(product);
        if (productNode.isMissingNode()) {
            return null;
        }

        if (product.equals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase())) {
            return productNode.path(PROJECT_BOM_URL_PROPERTY).asText(null);
        } else if (product.equals(SecurityProduct.COVERITY.name().toLowerCase())) {
            JsonNode issuesUrlNode = productNode.path(CONNECT_PROPERTY).path(RESULT_URL_PROPERTY);
            return issuesUrlNode.asText(null);
        } else if (product.equals(SecurityProduct.POLARIS.name().toLowerCase())
                || product.equals(SecurityProduct.SRM.name().toLowerCase())) {
            JsonNode issuesUrlNode =
                    productNode.path(PROJECT_PROPERTY).path(ISSUES_PROPERTY).path(URL_PROPERTY);
            return issuesUrlNode.asText(null);
        }

        return null;
    }

    public int calculateTotalIssues(JsonNode rootNode, String product) {
        JsonNode productNode = rootNode.path(DATA_PROPERTY).path(product);
        if (productNode.isMissingNode()) {
            return -1;
        }

        switch (SecurityProduct.valueOf(product.toUpperCase())) {
            case BLACKDUCKSCA:
                return calculateBlackDuckScaIssues(productNode);
            case COVERITY:
                return calculateCoverityIssues(productNode);
            case POLARIS:
                return calculatePolarisIssues(productNode);
            case SRM:
                return calculateSrmIssues(productNode);
            default:
                return -1;
        }
    }

    private int calculateBlackDuckScaIssues(JsonNode productNode) {
        JsonNode statusNode = productNode.path(POLICY_PROPERTY).path(STATUS_PROPERTY);
        return statusNode.isMissingNode() ? -1 : calculateIssues(statusNode);
    }

    private int calculateCoverityIssues(JsonNode productNode) {
        return productNode
                .path(CONNECT_PROPERTY)
                .path(POLICY_PROPERTY)
                .path(ISSUE_COUNT_PROPERTY)
                .asInt(-1);
    }

    private int calculatePolarisIssues(JsonNode productNode) {
        JsonNode testNode = productNode.path(TEST_PROPERTY);
        if (testNode.isMissingNode()) {
            return -1;
        }

        int totalIssues = 0;
        for (AssessmentType assessmentType : AssessmentType.values()) {
            totalIssues += calculateIssues(testNode.path(assessmentType.name()));
        }
        return totalIssues;
    }

    private int calculateSrmIssues(JsonNode productNode) {
        JsonNode analysisNode = productNode.path(ANALYSIS_PROPERTY);
        return analysisNode.isMissingNode() ? -1 : calculateIssues(analysisNode);
    }

    public int calculateIssues(JsonNode testNode) {
        if (!testNode.isMissingNode()) {
            JsonNode issuesNode = testNode.path(ISSUES_PROPERTY);
            if (!issuesNode.isMissingNode()) {
                int total = 0;
                for (IssueSeverities severity : IssueSeverities.values()) {
                    total += issuesNode.path(severity.name().toLowerCase()).asInt(0);
                }
                return total;
            }
        }
        return 0;
    }
}
