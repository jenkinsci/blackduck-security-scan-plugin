package io.jenkins.plugins.security.scan.global;

import com.fasterxml.jackson.databind.JsonNode;
import io.jenkins.plugins.security.scan.global.enums.AssessmentType;
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
        JsonNode productNode = getNodeIgnoreCase(rootNode, DATA_PROPERTY, product);
        if (productNode.isMissingNode()) {
            return null;
        }

        if (product.equals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase())) {
            return getNodeIgnoreCase(productNode, PROJECT_BOM_URL_PROPERTY).asText(null);
        } else if (product.equals(SecurityProduct.COVERITY.name().toLowerCase())) {
            JsonNode resultUrlNode = getNodeIgnoreCase(productNode, CONNECT_PROPERTY, RESULT_URL_PROPERTY);
            return resultUrlNode.asText(null);
        } else if (product.equals(SecurityProduct.POLARIS.name().toLowerCase())
                || product.equals(SecurityProduct.SRM.name().toLowerCase())) {
            JsonNode issuesUrlNode = getNodeIgnoreCase(productNode, PROJECT_PROPERTY, ISSUES_PROPERTY, URL_PROPERTY);
            return issuesUrlNode.asText(null);
        }

        return null;
    }

    public int calculateTotalIssues(JsonNode rootNode, String product) {
        JsonNode productNode = getNodeIgnoreCase(rootNode, DATA_PROPERTY, product);
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
        JsonNode statusNode = getNodeIgnoreCase(productNode, POLICY_PROPERTY, STATUS_PROPERTY);
        return statusNode.isMissingNode() ? -1 : calculateIssues(statusNode);
    }

    private int calculateCoverityIssues(JsonNode productNode) {
        JsonNode issueCountNode =
                getNodeIgnoreCase(productNode, CONNECT_PROPERTY, POLICY_PROPERTY, ISSUE_COUNT_PROPERTY);
        return issueCountNode.asInt(-1);
    }

    private int calculatePolarisIssues(JsonNode productNode) {
        JsonNode testNode = getNodeIgnoreCase(productNode, TEST_PROPERTY);
        if (testNode.isMissingNode()) {
            return -1;
        }

        int totalIssues = 0;
        for (AssessmentType assessmentType : AssessmentType.values()) {
            JsonNode assessmentTypeNode = getNodeIgnoreCase(testNode, assessmentType.name());
            JsonNode testsNode = getNodeIgnoreCase(assessmentTypeNode, TESTS_PROPERTY);
            JsonNode fullNode = getNodeIgnoreCase(testsNode, FULL_PROPERTY);
            if (!fullNode.isMissingNode()) {
                totalIssues += calculateIssues(fullNode);
            } else {
                JsonNode scaPackageNode = getNodeIgnoreCase(testsNode, SCA_PACKAGE_PROPERTY);
                JsonNode scaSignatureNode = getNodeIgnoreCase(testsNode, SCA_SIGNATURE_PROPERTY);
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
        JsonNode analysisNode = getNodeIgnoreCase(productNode, ANALYSIS_PROPERTY);
        return analysisNode.isMissingNode() ? -1 : calculateIssues(analysisNode);
    }

    public int calculateIssues(JsonNode testNode) {
        if (!testNode.isMissingNode()) {
            JsonNode issuesNode = getNodeIgnoreCase(testNode, ISSUES_PROPERTY);
            if (!issuesNode.isMissingNode()) {
                int total = 0;
                Iterator<String> fieldNames = issuesNode.fieldNames();
                while (fieldNames.hasNext()) {
                    String field = fieldNames.next();
                    total += issuesNode.path(field).asInt(0);
                }
                return total;
            }
        }
        return 0;
    }

    // Helper method for case-insensitive key lookup
    private JsonNode getNodeIgnoreCase(JsonNode node, String... keys) {
        JsonNode current = node;
        for (String key : keys) {
            if (current == null || current.isMissingNode()) return current;
            Iterator<String> fieldNamesIterator = current.fieldNames();
            boolean found = false;
            while (fieldNamesIterator.hasNext()) {
                String fieldName = fieldNamesIterator.next();
                if (fieldName.equalsIgnoreCase(key)) {
                    current = current.path(fieldName);
                    found = true;
                    break;
                }
            }
            if (!found) {
                current = current.path(key); // fallback
            }
        }
        return current;
    }
}
