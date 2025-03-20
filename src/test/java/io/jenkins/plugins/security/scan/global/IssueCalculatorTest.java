package io.jenkins.plugins.security.scan.global;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.junit.jupiter.api.Test;

public class IssueCalculatorTest {
    IssueCalculator issueCalculator = new IssueCalculator();

    @Test
    public void testGetIssuesUrl_ValidProduct() throws IOException {
        String jsonContent =
                "{" + "\"data\": {\"polaris\": {\"project\": {\"issues\": {\"url\": \"http://example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertEquals("http://example.com/issues", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_InvalidProduct() throws IOException {
        // Arrange
        String jsonContent = "{"
                + "\"data\": {\"product1\": {\"project\": {\"issues\": {\"url\": \"http://example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "invalidProduct";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertNull(issuesUrl);
    }

    @Test
    public void testCalculateTotalIssues() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"polaris\": {\"test\": {\"SAST\": {\"tests\": {\"full\": {\"issues\": {\"critical\": 2, \"high\": 3}}}}, \"SCA\": {\"tests\": {\"scaPackage\": {\"issues\": {\"medium\": 4, \"low\": 5}}}}}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";

        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);

        assertEquals(14, totalIssues);
    }

    @Test
    public void testCalculateIssues() throws IOException {
        String jsonContent = "{" + "\"issues\": {\"critical\": 2, \"high\": 3, \"medium\": 4, \"low\": 5}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode testNode = objectMapper.readTree(jsonContent);

        int totalIssues = issueCalculator.calculateIssues(testNode);

        assertEquals(14, totalIssues);
    }
}
