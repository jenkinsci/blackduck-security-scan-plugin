package io.jenkins.plugins.security.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.jenkins.plugins.security.scan.extension.SecurityScan;
import io.jenkins.plugins.security.scan.extension.freestyle.SecurityScanFreestyle;
import io.jenkins.plugins.security.scan.extension.pipeline.PrCommentScan;
import io.jenkins.plugins.security.scan.extension.pipeline.SecurityScanStep;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class RemovedParametersTest {

    private static final List<Class<?>> SECURITY_SCAN_TYPES =
            List.of(SecurityScanStep.class, SecurityScanFreestyle.class, SecurityScan.class, PrCommentScan.class);

    static Stream<String> removedParameters() {
        return Stream.of(
                "blackduck_url",
                "blackduck_token",
                "blackduck_install_directory",
                "blackduck_scan_full",
                "blackduck_scan_failure_severities",
                "blackduck_prComment_enabled",
                "blackduck_download_url",
                "blackduck_reports_sarif_create",
                "blackduck_reports_sarif_file_path",
                "blackduck_reports_sarif_groupSCAIssues",
                "blackduck_reports_sarif_severities",
                "blackduck_waitForScan",
                "blackduck_search_depth",
                "blackduck_config_path",
                "blackduck_args",
                "blackduck_execution_path",
                "synopsys_bridge_install_directory",
                "synopsys_bridge_download_url",
                "synopsys_bridge_download_version",
                "blackduck_prComment_enabled_actualValue",
                "blackduck_waitForScan_actualValue",
                "blackduck_reports_sarif_groupSCAIssues_temporary",
                "blackduckIntelligentScan");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("removedParameters")
    void securityScanTypes_withoutRemovedParameterTest(String parameter) {
        String accessorSuffix = Character.toUpperCase(parameter.charAt(0)) + parameter.substring(1);
        List<String> removedMembers =
                List.of(parameter, "get" + accessorSuffix, "is" + accessorSuffix, "set" + accessorSuffix);

        for (Class<?> type : SECURITY_SCAN_TYPES) {
            List<String> retainedMembers = removedMembers.stream()
                    .filter(member -> memberNamesOf(type).contains(member))
                    .collect(Collectors.toList());

            assertEquals(List.of(), retainedMembers, type.getSimpleName() + " still has removed members");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("removedParameters")
    void applicationConstants_withoutRemovedParameterTest(String parameter) {
        List<String> retainedConstants = Arrays.stream(ApplicationConstants.class.getDeclaredFields())
                .filter(field -> Modifier.isStatic(field.getModifiers()) && field.getType() == String.class)
                .filter(field -> parameter.equals(valueOf(field)))
                .map(Field::getName)
                .collect(Collectors.toList());

        assertEquals(List.of(), retainedConstants, "ApplicationConstants still defines a key for " + parameter);
    }

    private static List<String> memberNamesOf(Class<?> type) {
        return Stream.concat(
                        Arrays.stream(type.getDeclaredMethods()).map(Method::getName),
                        Arrays.stream(type.getDeclaredFields()).map(Field::getName))
                .collect(Collectors.toList());
    }

    private static Object valueOf(Field constant) {
        try {
            constant.setAccessible(true);
            return constant.get(null);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Unable to read constant " + constant.getName(), e);
        }
    }
}
