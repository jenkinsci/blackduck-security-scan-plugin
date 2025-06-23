handleBuildStepChange();

document.addEventListener('change', function () {
    handleBuildStepChange();
});

function hideParticularDiv(div) {
    if (div) div.style.display = 'none';
}

function showParticularDiv(div) {
    if (div) div.style.display = 'block';
}

function clearInputFields(div) {
    if (!div)
        return;

    const inputFields = div.querySelectorAll(
        'input[type="text"], input[type="checkbox"], select');
    inputFields.forEach(function (field) {
        if (field.type === 'text' || field.tagName.toLowerCase()
            === 'select') {
            field.value = '';
        } else if (field.type === 'checkbox') {
            if (field.name !== "_.srm_waitForScan" && field.name
                !== "_.polaris_waitForScan" && field.name
                !== "_.blackducksca_waitForScan" && field.name
                !== "_.coverity_waitForScan" && field.name
                !== "_.polaris_reports_sarif_groupSCAIssues" && field.name
                !== "_.blackducksca_reports_sarif_groupSCAIssues") {
                field.checked = false;
            }
        }
    });
}

function handleBuildStepChange() {
    document.querySelectorAll('.build-step-blackduck').forEach(element => {
        const selectedOption = element.querySelector('select[name="_.product"]')?.value;
        const polarisAssessmentModeOption = element.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
        const blackduckscaDiv = element.querySelector('#blackducksca');
        const coverityDiv = element.querySelector('#coverity');
        const polarisDiv = element.querySelector('#polaris');
        const srmDiv = element.querySelector('#srm');
        const sourceUploadDiv = element.querySelector('#source_upload');

        if (polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
            showParticularDiv(sourceUploadDiv);
        } else if (polarisAssessmentModeOption === 'CI' || polarisAssessmentModeOption === '') {
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
                validateProductField(element);
                toggleSarifParamsDivs(element);
                handleSarifReportSectionVisibility(element);
            } else if (selectedOption === 'coverity') {
                clearInputFields(blackduckscaDiv);
                hideParticularDiv(blackduckscaDiv);
                clearInputFields(polarisDiv);
                hideParticularDiv(polarisDiv);
                clearInputFields(srmDiv);
                hideParticularDiv(srmDiv);
                showParticularDiv(coverityDiv);
                validateProductField(element);
                validateCoverityFields(element);
            } else if (selectedOption === 'polaris') {
                clearInputFields(blackduckscaDiv);
                hideParticularDiv(blackduckscaDiv);
                clearInputFields(coverityDiv);
                hideParticularDiv(coverityDiv);
                clearInputFields(srmDiv);
                hideParticularDiv(srmDiv);
                showParticularDiv(polarisDiv);
                validateProductField(element);
                validatePolarisFields(element);
                toggleSarifParamsDivs(element);
                handleSarifReportSectionVisibility(element);
            } else if (selectedOption === 'srm') {
                clearInputFields(blackduckscaDiv);
                hideParticularDiv(blackduckscaDiv);
                clearInputFields(coverityDiv);
                hideParticularDiv(coverityDiv);
                clearInputFields(polarisDiv);
                hideParticularDiv(polarisDiv);
                showParticularDiv(srmDiv);
                validateProductField(element);
                validateSrmFields(element);
            } else if (selectedOption === 'select') {
                clearInputFields(blackduckscaDiv);
                clearInputFields(coverityDiv);
                clearInputFields(polarisDiv);
                clearInputFields(srmDiv);
                hideParticularDiv(blackduckscaDiv);
                hideParticularDiv(coverityDiv);
                hideParticularDiv(polarisDiv);
                hideParticularDiv(srmDiv);
                validateProductField(element);
        }
    });
}

function validateProductField(element) {
    element.querySelectorAll('.error_product_name').forEach(div => {
        const select = div.parentElement.querySelector('select[name="_.product"]');
        div.style.display = (select?.value === 'select') ? "block" : "none";
    });
}

function validateCoverityFields(element) {
    const coverityProjectName = element.querySelector('input[name="_.coverity_project_name"]')?.value;
    const coverityStreamName = element.querySelector('input[name="_.coverity_stream_name"]')?.value;
    const errorCoverityProjectNameDiv = element.querySelector("#error_coverity_project_name");
    const errorCoverityStreamNameDiv = element.querySelector("#error_coverity_stream_name");

    errorCoverityProjectNameDiv.style.display = coverityProjectName ? "none" : "block";
    errorCoverityStreamNameDiv.style.display = coverityStreamName ? "none" : "block";
}

function validatePolarisFields(element) {
    const fields = [
        { name: 'polaris_application_name', error: '#error_polaris_application_name' },
        { name: 'polaris_project_name', error: '#error_polaris_project_name' },
        { name: 'polaris_assessment_types', error: '#error_polaris_assessment_types' },
        { name: 'polaris_branch_name', error: '#error_polaris_branch_name' }
    ];
    fields.forEach(({ name, error }) => {
        const value = element.querySelector(`input[name="_.${name}"]`)?.value;
        const errorDiv = element.querySelector(error);
        if (errorDiv) errorDiv.style.display = value ? "none" : "block";
    });
}

function validateSrmFields(element) {
    const srmProjectName = element.querySelector('input[name="_.srm_project_name"]')?.value;
    const srmAssessmentTypes = element.querySelector('input[name="_.srm_assessment_types"]')?.value;
    const srmProjectId = element.querySelector('input[name="_.srm_project_id"]')?.value;
    const errorSrmProjectNameDiv = element.querySelector("#error_srm_project_name");
    const errorSrmProjectIdDiv = element.querySelector("#error_srm_project_id");
    const errorSrmAssessmentTypesDiv = element.querySelector("#error_srm_assessment_types");

    const showProjectError = !srmProjectName && !srmProjectId;
    if (errorSrmProjectNameDiv) errorSrmProjectNameDiv.style.display = showProjectError ? "block" : "none";
    if (errorSrmProjectIdDiv) errorSrmProjectIdDiv.style.display = showProjectError ? "block" : "none";
    if (errorSrmAssessmentTypesDiv) errorSrmAssessmentTypesDiv.style.display = srmAssessmentTypes ? "none" : "block";
}

function toggleSarifParamsDivs(element) {
    const blackduckCheckbox = element.querySelector(
        'input[name="_.blackducksca_reports_sarif_create"]')
    const polarisCheckbox = element.querySelector(
        'input[name="_.polaris_reports_sarif_create"]')

    const blackduckSarifParamSection = element.querySelector(
        '#blackducksca_sarif_params')
    const polarisSarifParamSection = element.querySelector(
        '#polaris_sarif_params')

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

function handleSarifReportSectionVisibility(element) {
    const selectedOption = element.querySelector('select[name="_.product"]')?.value;
    const blackduckscaWaitForScanEnabled = element.querySelector('input[name="_.blackducksca_waitForScan"]')?.checked;
    const polarisWaitForScanEnabled = element.querySelector('input[name="_.polaris_waitForScan"]')?.checked;

    if (selectedOption === 'blackducksca') {
        const blackduckSACSarif_section = element.querySelector('#blackducksca_sarif_report_sec');
        if (blackduckSACSarif_section) {
            if (!blackduckscaWaitForScanEnabled) {
                hideParticularDiv(blackduckSACSarif_section);
                clearInputFields(blackduckSACSarif_section);
            } else {
                showParticularDiv(blackduckSACSarif_section);
            }
        }
    } else if (selectedOption === 'polaris') {
        const polarisSarif_section = element.querySelector('#polaris_sarif_report_sec');
        if (polarisSarif_section) {
            if (!polarisWaitForScanEnabled) {
                hideParticularDiv(polarisSarif_section);
                clearInputFields(polarisSarif_section);
            } else {
                showParticularDiv(polarisSarif_section);
            }
        }
    }
}
