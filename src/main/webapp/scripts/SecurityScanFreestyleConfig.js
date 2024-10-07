var selectedOption = document.querySelector('select[name="_.product"]')?.value;
var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
var sourceUploadDiv = document.getElementById('source_upload');


console.log("Selected option in the beginning: ", selectedOption)

if (selectedOption && selectedOption !== 'select') {
    document.getElementById(selectedOption).style.display = 'block';
    validateProductField();
    validateCoverityFields();
    validatePolarisFields();
    validateSrmFields();

    if (selectedOption === 'polaris' && polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
        showParticularDiv(sourceUploadDiv);
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
        var inputFields = div.querySelectorAll('input[type="text"], input[type="checkbox"]');
        inputFields.forEach(function (field) {
            if (field.type === 'text') {
                field.value = '';
            } else if (field.type === 'checkbox') {
                if (field.name !== "_.srm_waitForScan" && field.name !== "_.polaris_waitForScan" && field.name !== "_.blackduck_waitForScan" && field.name !== "_.coverity_waitForScan" && field.name !== "_.polaris_reports_sarif_groupSCAIssues" && field.name !== "_.blackduck_reports_sarif_groupSCAIssues") {
                    field.checked = false;
                }
            }
        });
        // clears polaris assessment mode dropdown value
        var selectedOption = document.querySelector('select[name="_.product"]')?.value;
        if (selectedOption !== 'polaris') {
            var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]');
            if (polarisAssessmentModeOption) {
                polarisAssessmentModeOption.value = ""
            }
        }
    }
}


document.addEventListener('change', function () {
    var selectedOption = document.querySelector('select[name="_.product"]')?.value;
    var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;

    console.log(":++++++++++++++ ", selectedOption)


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
    } else if (selectedOption === 'select') {
        clearInputFields(blackduckscaDiv);
        clearInputFields(coverityDiv);
        clearInputFields(polarisDiv);
        clearInputFields(srmDiv);
        hideParticularDiv(blackduckscaDiv);
        hideParticularDiv(coverityDiv);
        hideParticularDiv(polarisDiv);
        hideParticularDiv(srmDiv);
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

    if (!srmProjectName && !srmProjectId) {
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