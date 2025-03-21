package io.jenkins.plugins.security.scan.global;

import com.fasterxml.jackson.databind.JsonNode;
import io.jenkins.plugins.security.scan.global.enums.AssessmentType;
import io.jenkins.plugins.security.scan.global.enums.IssueSeverities;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;

public class IssueCalculator {

    private static final String DATA_PROPERTY = "data";
    private static final String PROJECT_PROPERTY = "project";
    private static final String ISSUES_PROPERTY = "issues";
    private static final String URL_PROPERTY = "url";
    private static final String TEST_PROPERTY = "test";
    private static final String TESTS_PROPERTY = "tests";
    private static final String FULL_PROPERTY = "full";
    private static final String SCA_PACKAGE_PROPERTY = "scaPackage";
    private static final String SCA_SIGNATURE_PROPERTY = "scaSignature";
    private static final String ANALYSIS_PROPERTY = "analysis";
    private static final String PROJECT_BOM_URL_PROPERTY = "projectBomUrl";
    private static final String RESULT_URL_PROPERTY = "resultURL";
    private static final String POLICY_PROPERTY = "policy";
    private static final String STATUS_PROPERTY = "status";
    private static final String CONNECT_PROPERTY = "connect";
    private static final String ISSUE_COUNT_PROPERTY = "issueCount";

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
            JsonNode assessmentTypeNode = testNode.path(assessmentType.name());
            if (assessmentTypeNode.isMissingNode()) {
                assessmentTypeNode = testNode.path(assessmentType.name().toLowerCase());
            }
            JsonNode testsNode = assessmentTypeNode.path(TESTS_PROPERTY);
            JsonNode fullNode = testsNode.path(FULL_PROPERTY);
            if (!fullNode.isMissingNode()) {
                totalIssues += calculateIssues(fullNode);
            } else {
                JsonNode scaPackageNode = testsNode.path(SCA_PACKAGE_PROPERTY);
                JsonNode scaSignatureNode = testsNode.path(SCA_SIGNATURE_PROPERTY);
                if (!scaSignatureNode.isMissingNode()) {
                    totalIssues += calculateIssues(scaSignatureNode);
                }
                if (!scaPackageNode.isMissingNode()) {
                    totalIssues += calculateIssues(scaPackageNode);
                }
            }
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
