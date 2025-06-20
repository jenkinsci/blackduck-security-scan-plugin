handleBuildStepChange();
bindProductDropdowns();

document.addEventListener('change', function () {
    handleBuildStepChange();
});

document.addEventListener('click', function (event) {
    if (event.target && event.target.matches('[name="_.product"]')) {
        updateProductDropdowns();
        bindProductDropdowns();
    }
});

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
}

function updateProductDropdowns() {
    let productSelectElem = document.querySelectorAll('[name="_.product"]');
    const selectedProducts = new Set();
    productSelectElem.forEach(select => {
        if (select.value && select.value !== 'select') {
            selectedProducts.add(select.value);
        }
    });

    // Disable options already selected in other dropdowns
    productSelectElem.forEach(select => {
        const currentValue = select.value;
        Array.from(select.options).forEach(option => {
            if (
                option.value !== 'select' &&
                selectedProducts.has(option.value) &&
                option.value !== currentValue
            ) {
                option.disabled = true;
            } else {
                option.disabled = false;
            }
        });
    });
}

function bindProductDropdowns() {
    document.querySelectorAll('[name="_.product"]').forEach(select => {
        select.addEventListener('click', updateProductDropdowns);
    });
}

function handleBuildStepChange() {
    document.querySelectorAll('.build-step-blackduck').forEach(
        function (element) {
            const selectedOption = element.querySelector(
                'select[name="_.product"]')?.value;
            const polarisAssessmentModeOption = element.querySelector(
                'select[name="_.polaris_assessment_mode"]')?.value;
            const blackduckscaDiv = element.querySelector('#blackducksca');
            const coverityDiv = element.querySelector('#coverity');
            const polarisDiv = element.querySelector('#polaris');
            const srmDiv = element.querySelector('#srm');
            const sourceUploadDiv = element.querySelector('#source_upload');

            if (polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
                showParticularDiv(sourceUploadDiv);
            }

            if (polarisAssessmentModeOption === 'CI'
                || polarisAssessmentModeOption === '') {
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
    const errorProductDivs = element.querySelectorAll('.error_product_name');
    errorProductDivs.forEach(function (div) {
        const select = div.parentElement.querySelector(
            'select[name="_.product"]');
        const selectedOption = select?.value;
        if (selectedOption === 'select') {
            div.style.display = "block";
        } else {
            div.style.display = "none";
        }
    });
}

function validateCoverityFields(element) {
    const coverityProjectName = element.querySelector(
        'input[name="_.coverity_project_name"]')?.value;
    const coverityStreamName = element.querySelector(
        'input[name="_.coverity_stream_name"]')?.value;
    const errorCoverityProjectNameDiv = element.querySelector(
        "#error_coverity_project_name");
    const errorCoverityStreamNameDiv = element.querySelector(
        "#error_coverity_stream_name");

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

function validatePolarisFields(element) {
    const polarisApplicationName = element.querySelector(
        'input[name="_.polaris_application_name"]')?.value;
    const polarisProjectName = element.querySelector(
        'input[name="_.polaris_project_name"]')?.value;
    const polarisAssessmentTypes = element.querySelector(
        'input[name="_.polaris_assessment_types"]')?.value;
    const polarisBranchName = element.querySelector(
        'input[name="_.polaris_branch_name"]')?.value;
    const errorPolarisApplicationNameDiv = element.querySelector(
        "#error_polaris_application_name");
    const errorPolarisProjectNameDiv = element.querySelector(
        "#error_polaris_project_name");
    const errorPolarisAssessmentTypesDiv = element.querySelector(
        "#error_polaris_assessment_types");
    const errorPolarisBranchNameDiv = element.querySelector(
        "#error_polaris_branch_name");

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

function validateSrmFields(element) {
    const srmProjectName = element.querySelector(
        'input[name="_.srm_project_name"]')?.value;
    const srmAssessmentTypes = element.querySelector(
        'input[name="_.srm_assessment_types"]')?.value;
    const srmProjectId = element.querySelector(
        'input[name="_.srm_project_id"]')?.value;
    const errorSrmProjectNameDiv = element.querySelector(
        "#error_srm_project_name");
    const errorSrmProjectIdDiv = element.querySelector("#error_srm_project_id");
    const errorSrmAssessmentTypesDiv = element.querySelector(
        "#error_srm_assessment_types");

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
    const selectedOption = element.querySelector(
        'select[name="_.product"]')?.value;
    const blackduckscaWaitForScanEnabled = element.querySelector(
        'input[name="_.blackducksca_waitForScan"]').checked;
    const polarisWaitForScanEnabled = element.querySelector(
        'input[name="_.polaris_waitForScan"]').checked;

    if (selectedOption === 'blackducksca') {
        const blackduckSACSarif_section = element.querySelector(
            '#blackducksca_sarif_report_sec');
        if (blackduckscaWaitForScanEnabled == false) {
            hideParticularDiv(blackduckSACSarif_section);
            clearInputFields(blackduckSACSarif_section);
        } else if (blackduckscaWaitForScanEnabled == true) {
            showParticularDiv(blackduckSACSarif_section);
        }
    } else if (selectedOption === 'polaris') {
        const polarisSarif_section = element.querySelector(
            '#polaris_sarif_report_sec');
        if (polarisWaitForScanEnabled == false) {
            hideParticularDiv(polarisSarif_section);
            clearInputFields(polarisSarif_section);
        } else if (polarisWaitForScanEnabled == true) {
            showParticularDiv(polarisSarif_section);
        }
    }

}