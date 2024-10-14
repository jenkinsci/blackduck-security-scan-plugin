var selectedOption = document.querySelector('select[name="_.product"]')?.value;
var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
var sourceUploadDiv = document.getElementById('source_upload');

if (selectedOption &amp;&amp; selectedOption !== 'select') {
    document.getElementById(selectedOption).style.display = 'block';
    document.getElementById('bridge_cli_sec').style.display = 'block';

    validateProductField();
    validateCoverityFields();
    validatePolarisFields();
    validateSrmFields();
    if (selectedOption === 'polaris') {
        toggleSarifParamsDivs();
        if(polarisAssessmentModeOption === 'SOURCE_UPLOAD'){
            showParticularDiv(sourceUploadDiv);
        }
    }else if(selectedOption === 'blackducksca') {
        toggleSarifParamsDivs();
        handleSarifReportSectionVisibility();
    }
}

function hideParticularDiv(div) {
    if (div) {
        div.style.display = 'none';
    }
}

function showParticularDiv(div) {
    if (div) {
        div.style.display = 'block';
    }
}

function clearInputFields(div) {
    if (div) {
        var inputFields = div.querySelectorAll('input[type="text"], input[type="checkbox"], select');
        inputFields.forEach(function (field) {
            if (field.type === 'text' || field.tagName.toLowerCase() === 'select') {
                field.value = '';
            } else if (field.type === 'checkbox') {
                if (field.name !== "_.srm_waitForScan" &amp;&amp; field.name !== "_.polaris_waitForScan" &amp;&amp; field.name !== "_.blackducksca_waitForScan" &amp;&amp; field.name !== "_.coverity_waitForScan" &amp;&amp; field.name !== "_.polaris_reports_sarif_groupSCAIssues" &amp;&amp; field.name !== "_.blackducksca_reports_sarif_groupSCAIssues") {
                    field.checked = false;
                }
            }
        });
    }
}

document.addEventListener('change', function () {
    var selectedOption = document.querySelector('select[name="_.product"]')?.value;
    var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
    var bridgeCliSecDiv = document.getElementById('bridge_cli_sec');
    var blackduckscaDiv = document.getElementById('blackducksca');
    var coverityDiv = document.getElementById('coverity');
    var polarisDiv = document.getElementById('polaris');
    var srmDiv = document.getElementById('srm');
    var sourceUploadDiv = document.getElementById('source_upload');

    if (polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
        showParticularDiv(sourceUploadDiv);
    }

    if (polarisAssessmentModeOption === 'CI' || polarisAssessmentModeOption === '') {
        clearInputFields(sourceUploadDiv);
        hideParticularDiv(sourceUploadDiv);
    }

    if (selectedOption === 'blackducksca') {
        clearInputFields(coverityDiv);
        hideParticularDiv(coverityDiv);
        clearInputFields(polarisDiv);
        hideParticularDiv(polarisDiv);
        clearInputFields(srmDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(blackduckscaDiv);
        validateProductField();
        toggleSarifParamsDivs();
        handleSarifReportSectionVisibility();
        showParticularDiv(bridgeCliSecDiv);
    } else if (selectedOption === 'coverity') {
        clearInputFields(blackduckscaDiv);
        hideParticularDiv(blackduckscaDiv);
        clearInputFields(polarisDiv);
        hideParticularDiv(polarisDiv);
        clearInputFields(srmDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(coverityDiv);
        validateProductField();
        validateCoverityFields();
        showParticularDiv(bridgeCliSecDiv);
    } else if (selectedOption === 'polaris') {
        clearInputFields(blackduckscaDiv);
        hideParticularDiv(blackduckscaDiv);
        clearInputFields(coverityDiv);
        hideParticularDiv(coverityDiv);
        clearInputFields(srmDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(polarisDiv);
        validateProductField();
        validatePolarisFields();
        toggleSarifParamsDivs();
        handleSarifReportSectionVisibility();
        showParticularDiv(bridgeCliSecDiv);
    } else if (selectedOption === 'srm') {
        clearInputFields(blackduckscaDiv);
        hideParticularDiv(blackduckscaDiv);
        clearInputFields(coverityDiv);
        hideParticularDiv(coverityDiv);
        clearInputFields(polarisDiv);
        hideParticularDiv(polarisDiv);
        showParticularDiv(srmDiv);
        validateProductField();
        validateSrmFields();
        showParticularDiv(bridgeCliSecDiv);
    } else if (selectedOption === 'select') {
        clearInputFields(blackduckscaDiv);
        clearInputFields(coverityDiv);
        clearInputFields(polarisDiv);
        clearInputFields(srmDiv);
        hideParticularDiv(blackduckscaDiv);
        hideParticularDiv(coverityDiv);
        hideParticularDiv(polarisDiv);
        hideParticularDiv(srmDiv);
        hideParticularDiv(bridgeCliSecDiv);
        validateProductField();
    }

});

function validateProductField() {
    var errorProductDiv = document.getElementById("error_product_name");
    var selectedOption = document.querySelector('select[name="_.product"]')?.value;
    if (selectedOption === 'select') {
        errorProductDiv.style.display = "block";
    } else {
        errorProductDiv.style.display = "none";
    }
}

function validateCoverityFields() {
    var coverityProjectName = document.querySelector('input[name="_.coverity_project_name"]')?.value;
    var coverityStreamName = document.querySelector('input[name="_.coverity_stream_name"]')?.value;
    var errorCoverityProjectNameDiv = document.getElementById("error_coverity_project_name");
    var errorCoverityStreamNameDiv = document.getElementById("error_coverity_stream_name");

    if (!coverityProjectName) {
        errorCoverityProjectNameDiv.style.display = "block";
    } else {
        errorCoverityProjectNameDiv.style.display = "none";
    }

    if (!coverityStreamName) {
        errorCoverityStreamNameDiv.style.display = "block";
    } else {
        errorCoverityStreamNameDiv.style.display = "none";
    }
}

function validatePolarisFields() {
    var polarisApplicationName = document.querySelector('input[name="_.polaris_application_name"]')?.value;
    var polarisProjectName = document.querySelector('input[name="_.polaris_project_name"]')?.value;
    var polarisAssessmentTypes = document.querySelector('input[name="_.polaris_assessment_types"]')?.value;
    var polarisBranchName = document.querySelector('input[name="_.polaris_branch_name"]')?.value;
    var errorPolarisApplicationNameDiv = document.getElementById("error_polaris_application_name");
    var errorPolarisProjectNameDiv = document.getElementById("error_polaris_project_name");
    var errorPolarisAssessmentTypesDiv = document.getElementById("error_polaris_assessment_types");
    var errorPolarisBranchNameDiv = document.getElementById("error_polaris_branch_name");

    if (!polarisApplicationName) {
        errorPolarisApplicationNameDiv.style.display = "block";
    } else {
        errorPolarisApplicationNameDiv.style.display = "none";
    }

    if (!polarisProjectName) {
        errorPolarisProjectNameDiv.style.display = "block";
    } else {
        errorPolarisProjectNameDiv.style.display = "none";
    }

    if (!polarisAssessmentTypes) {
        errorPolarisAssessmentTypesDiv.style.display = "block";
    } else {
        errorPolarisAssessmentTypesDiv.style.display = "none";
    }

    if (!polarisBranchName) {
        errorPolarisBranchNameDiv.style.display = "block";
    } else {
        errorPolarisBranchNameDiv.style.display = "none";
    }

}

function validateSrmFields() {
    var srmProjectName = document.querySelector('input[name="_.srm_project_name"]')?.value;
    var srmAssessmentTypes = document.querySelector('input[name="_.srm_assessment_types"]')?.value;
    var srmProjectId = document.querySelector('input[name="_.srm_project_id"]')?.value;
    var errorSrmProjectNameDiv = document.getElementById("error_srm_project_name");
    var errorSrmProjectIdDiv = document.getElementById("error_srm_project_id");
    var errorSrmAssessmentTypesDiv = document.getElementById("error_srm_assessment_types");

    if (!srmProjectName &amp;&amp; !srmProjectId) {
        errorSrmProjectNameDiv.style.display = "block";
        errorSrmProjectIdDiv.style.display = "block";
    } else {
        errorSrmProjectNameDiv.style.display = "none";
        errorSrmProjectIdDiv.style.display = "none";
    }

    if (!srmAssessmentTypes) {
        errorSrmAssessmentTypesDiv.style.display = "block";
    } else {
        errorSrmAssessmentTypesDiv.style.display = "none";
    }
}

function toggleSarifParamsDivs() {
    var blackduckCheckbox = document.querySelector('input[name="_.blackducksca_reports_sarif_create"]')
    var polarisCheckbox = document.querySelector('input[name="_.polaris_reports_sarif_create"]')

    var blackduckSarifParamSection = document.getElementById('blackducksca_sarif_params')
    var polarisSarifParamSection = document.getElementById('polaris_sarif_params')

    if (polarisCheckbox.checked) {
        polarisSarifParamSection.style.display = 'block';
    } else {
        polarisSarifParamSection.style.display = 'none';
        clearInputFields(polarisSarifParamSection);
    }

    if (blackduckCheckbox.checked) {
        blackduckSarifParamSection.style.display = 'block';
    } else {
        blackduckSarifParamSection.style.display = 'none';
        clearInputFields(blackduckSarifParamSection);
    }
}

function handleSarifReportSectionVisibility() {
    var selectedOption = document.querySelector('select[name="_.product"]')?.value;
    var blackduckscaWaitForScanEnabled = document.querySelector('input[name="_.blackducksca_waitForScan"]').checked;
    var polarisWaitForScanEnabled = document.querySelector('input[name="_.polaris_waitForScan"]').checked;

    if (selectedOption === 'blackducksca'){
        var blackduckSACSarif_section = document.getElementById('blackducksca_sarif_report_sec');
        if(blackduckscaWaitForScanEnabled == false){
            hideParticularDiv(blackduckSACSarif_section);
            clearInputFields(blackduckSACSarif_section);
        }else if(blackduckscaWaitForScanEnabled == true){
            showParticularDiv(blackduckSACSarif_section);
        }
    }else if (selectedOption === 'polaris'){
        var polarisSarif_section = document.getElementById('polaris_sarif_report_sec');
        if(polarisWaitForScanEnabled == false){
            hideParticularDiv(polarisSarif_section);
            clearInputFields(polarisSarif_section);
        }else if(polarisWaitForScanEnabled == true){
            showParticularDiv(polarisSarif_section);
        }
    }

}