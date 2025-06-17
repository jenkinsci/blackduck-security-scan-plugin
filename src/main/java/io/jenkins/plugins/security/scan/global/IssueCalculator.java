package io.jenkins.plugins.security.scan.global;

import com.fasterxml.jackson.databind.JsonNode;
import io.jenkins.plugins.security.scan.global.enums.AssessmentType;
import io.jenkins.plugins.security.scan.global.enums.IssueSeverities;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import java.util.Iterator;

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
        JsonNode productNode = getCaseInsensitiveNode(rootNode.path(DATA_PROPERTY), product);
        if (productNode.isMissingNode()) {
            return null;
        }

        if (product.equals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase())) {
            return getCaseInsensitiveNode(productNode, PROJECT_BOM_URL_PROPERTY).asText(null);
        } else if (product.equals(SecurityProduct.COVERITY.name().toLowerCase())) {
            JsonNode connectNode = getCaseInsensitiveNode(productNode, CONNECT_PROPERTY);
            JsonNode resultUrlNode = getCaseInsensitiveNode(connectNode, RESULT_URL_PROPERTY);
            return resultUrlNode.asText(null);
        } else if (product.equals(SecurityProduct.POLARIS.name().toLowerCase())
                || product.equals(SecurityProduct.SRM.name().toLowerCase())) {
            JsonNode projectNode = getCaseInsensitiveNode(productNode, PROJECT_PROPERTY);
            JsonNode issuesNode = getCaseInsensitiveNode(projectNode, ISSUES_PROPERTY);
            JsonNode issuesUrlNode = getCaseInsensitiveNode(issuesNode, URL_PROPERTY);
            return issuesUrlNode.asText(null);
        }

        return null;
    }

    public int calculateTotalIssues(JsonNode rootNode, String product) {
        JsonNode productNode = getCaseInsensitiveNode(rootNode.path(DATA_PROPERTY), product);
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
        JsonNode policyNode = getCaseInsensitiveNode(productNode, POLICY_PROPERTY);
        JsonNode statusNode = getCaseInsensitiveNode(policyNode, STATUS_PROPERTY);
        return statusNode.isMissingNode() ? -1 : calculateIssues(statusNode);
    }

    private int calculateCoverityIssues(JsonNode productNode) {
        JsonNode connectNode = getCaseInsensitiveNode(productNode, CONNECT_PROPERTY);
        JsonNode policyNode = getCaseInsensitiveNode(connectNode, POLICY_PROPERTY);
        JsonNode issueCountNode = getCaseInsensitiveNode(policyNode, ISSUE_COUNT_PROPERTY);
        return issueCountNode.asInt(-1);
    }

    private int calculatePolarisIssues(JsonNode productNode) {
        JsonNode testNode = getCaseInsensitiveNode(productNode, TEST_PROPERTY);
        if (testNode.isMissingNode()) {
            return -1;
        }

        int totalIssues = 0;
        for (AssessmentType assessmentType : AssessmentType.values()) {
            JsonNode assessmentTypeNode = getCaseInsensitiveNode(testNode, assessmentType.name());
            if (assessmentTypeNode.isMissingNode()) {
                assessmentTypeNode =
                        getCaseInsensitiveNode(testNode, assessmentType.name().toLowerCase());
            }
            JsonNode testsNode = getCaseInsensitiveNode(assessmentTypeNode, TESTS_PROPERTY);
            JsonNode fullNode = getCaseInsensitiveNode(testsNode, FULL_PROPERTY);
            if (!fullNode.isMissingNode()) {
                totalIssues += calculateIssues(fullNode);
            } else {
                JsonNode scaPackageNode = getCaseInsensitiveNode(testsNode, SCA_PACKAGE_PROPERTY);
                JsonNode scaSignatureNode = getCaseInsensitiveNode(testsNode, SCA_SIGNATURE_PROPERTY);
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
        JsonNode analysisNode = getCaseInsensitiveNode(productNode, ANALYSIS_PROPERTY);
        return analysisNode.isMissingNode() ? -1 : calculateIssues(analysisNode);
    }

    public int calculateIssues(JsonNode testNode) {
        if (!testNode.isMissingNode()) {
            JsonNode issuesNode = getCaseInsensitiveNode(testNode, ISSUES_PROPERTY);
            if (!issuesNode.isMissingNode()) {
                int total = 0;
                for (IssueSeverities severity : IssueSeverities.values()) {
                    total += getCaseInsensitiveNode(issuesNode, severity.name()).asInt(0);
                }
                return total;
            }
        }
        return 0;
    }

    // Helper method for case-insensitive key lookup
    private JsonNode getCaseInsensitiveNode(JsonNode node, String key) {
        if (node == null || node.isMissingNode()) return node;
        Iterator<String> fieldNamesIterator = node.fieldNames();
        while (fieldNamesIterator.hasNext()) {
            String fieldName = fieldNamesIterator.next();
            if (fieldName.equalsIgnoreCase(key)) {
                return node.get(fieldName);
            }
        }
        return node.path(key); // fallback to default
    }
}
