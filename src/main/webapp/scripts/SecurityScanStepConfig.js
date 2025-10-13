var securityProduct = document.querySelector('select[name="_.product"]');
var blackduckscaDiv = document.getElementById('blackducksca');
var coverityDiv = document.getElementById('coverity');
var polarisDiv = document.getElementById('polaris');
var srmDiv = document.getElementById('srm');
var blackduckscaToolConfigDiv = document.getElementById('blackducksca-tool-configuration');
var coverityToolConfigDiv = document.getElementById('coverity-tool-configuration');

function hideAllDivs() {
    blackduckscaDiv.style.display = 'none';
    coverityDiv.style.display = 'none';
    polarisDiv.style.display = 'none';
    srmDiv.style.display = 'none';
    blackduckscaToolConfigDiv.style.display = 'none';
    coverityToolConfigDiv.style.display = 'none';
}

function clearAllFields() {
    clearInputFields(blackduckscaDiv);
    clearInputFields(coverityDiv);
    clearInputFields(polarisDiv);
    clearInputFields(srmDiv);
    clearInputFields(blackduckscaToolConfigDiv);
    clearInputFields(coverityToolConfigDiv);
}

function showParticularDiv(div) {
    if (div) {
        div.style.display = 'block';
    }
}

function hideParticularDiv(div) {
    if (div) {
        div.style.display = 'none';
    }
}

function clearInputFields(div) {
    if (div) {
        var inputFields = div.querySelectorAll('input[type="text"], input[type="checkbox"], input[type="radio"], select');
        inputFields.forEach(function(field) {
            if (field.type === 'text' || field.tagName.toLowerCase() === 'select') {
                field.value = '';
            } else if (field.type === 'checkbox') {
                field.checked = false;
            } else if (field.type === 'radio') {
                if (field.name.endsWith("blackducksca_scan_full")) {
                    if (field.value === "") {
                        field.checked = true; // Set "Auto" as default
                    } else {
                        field.checked = false;
                    }
                }
            }
        });
    }
}

function setCheckboxToDefaultTrue(names) {
    names.forEach(function(name) {
        var checkbox = document.getElementsByName(name);
        if (checkbox && checkbox.length > 0) {
            checkbox[0].checked = true;

        }
    });
}

securityProduct.addEventListener('change', function() {
    var selectedOption = securityProduct.value;
    clearAllFields();
    if (selectedOption == 'blackducksca') {
        hideParticularDiv(coverityDiv);
        hideParticularDiv(polarisDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(blackduckscaDiv);
        hideParticularDiv(coverityToolConfigDiv);
        showParticularDiv(blackduckscaToolConfigDiv);
        setCheckboxToDefaultTrue(['_.blackducksca_reports_sarif_groupSCAIssues', '_.blackducksca_waitForScan']);
    } else if (selectedOption == 'coverity') {
        hideParticularDiv(blackduckscaDiv);
        hideParticularDiv(polarisDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(coverityDiv);
        hideParticularDiv(blackduckscaToolConfigDiv);
        showParticularDiv(coverityToolConfigDiv);
        setCheckboxToDefaultTrue(['_.coverity_waitForScan']);
    } else if (selectedOption == 'polaris') {
        hideParticularDiv(blackduckscaDiv);
        hideParticularDiv(coverityDiv);
        hideParticularDiv(srmDiv);
        showParticularDiv(polarisDiv);
        showParticularDiv(blackduckscaToolConfigDiv);
        showParticularDiv(coverityToolConfigDiv);
        setCheckboxToDefaultTrue(['_.polaris_reports_sarif_groupSCAIssues', '_.polaris_waitForScan']);
    } else if (selectedOption == 'srm') {
        hideParticularDiv(blackduckscaDiv);
        hideParticularDiv(coverityDiv);
        hideParticularDiv(polarisDiv);
        showParticularDiv(srmDiv);
        showParticularDiv(blackduckscaToolConfigDiv);
        showParticularDiv(coverityToolConfigDiv);
        setCheckboxToDefaultTrue(['_.srm_waitForScan']);
    } else if (selectedOption == '') {
        hideAllDivs();
    }
});

document.addEventListener('change', function(event) {
    var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
    var sourceUploadDiv = document.getElementById('source_upload');

    if (polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
        showParticularDiv(sourceUploadDiv);
    }

    if (polarisAssessmentModeOption === 'CI' || polarisAssessmentModeOption === '') {
        clearInputFields(sourceUploadDiv);
        hideParticularDiv(sourceUploadDiv);
    }

    toggleSarifParamsDivs(event);
    togglePrCommentDivs();
    toggleFixPrParamsDivs();
    handlePostMergeWorkflowSectionsVisibility();
});

function toggleSarifParamsDivs(event) {
    var selectedOption = securityProduct.value;
    if (selectedOption == "blackducksca") {
        var blackduckCheckbox = document.querySelector('input[name="_.blackducksca_reports_sarif_create"]')
        var blackduckSarifParamSection = document.getElementById('blackducksca_sarif_params')
        if (blackduckCheckbox.checked) {
            blackduckSarifParamSection.style.display = 'block';
        } else {
            blackduckSarifParamSection.style.display = 'none';
            clearInputFields(blackduckSarifParamSection);
        }
        if(event.target.name == "_.blackducksca_reports_sarif_create" ){
            setCheckboxToDefaultTrue(['_.blackducksca_reports_sarif_groupSCAIssues']);
        }
    } else if (selectedOption == "polaris") {
        var polarisCheckbox = document.querySelector('input[name="_.polaris_reports_sarif_create"]')
        var polarisSarifParamSection = document.getElementById('polaris_sarif_params')

        if (polarisCheckbox.checked) {
            polarisSarifParamSection.style.display = 'block';
        } else {
            polarisSarifParamSection.style.display = 'none';
            clearInputFields(polarisSarifParamSection);
        }
        if(event.target.name == "_.polaris_reports_sarif_create"){
            setCheckboxToDefaultTrue(['_.polaris_reports_sarif_groupSCAIssues']);
        }
    }
}

function togglePrCommentDivs() {
    const selectedOption = securityProduct.value;
    let checkbox, section;

    if (selectedOption === "polaris") {
        checkbox = document.querySelector('input[name="_.polaris_prComment_enabled"]');
        section = document.getElementById('polaris_pr_comment_params');
    } else if (selectedOption === "coverity") {
        checkbox = document.querySelector('input[name="_.coverity_prComment_enabled"]');
        section = document.getElementById('coverity_pr_comment_params');
    } else {
        return;
    }

    if (!checkbox || !section) return;

    if (checkbox.checked) {
        section.style.display = 'block';
    } else {
        section.style.display = 'none';
        clearInputFields(section);
    }
}

function toggleFixPrParamsDivs() {
    var selectedOption = securityProduct.value;
    if (selectedOption == "blackducksca") {
        var blackduckFixPrCheckbox = document.querySelector('input[name="_.blackducksca_fixpr_enabled"]')
        var blackduckFixPrParamSection = document.getElementById('blackducksca_fixPr_params')
        if (blackduckFixPrCheckbox.checked) {
            blackduckFixPrParamSection.style.display = 'block';
        } else {
            blackduckFixPrParamSection.style.display = 'none';
            clearInputFields(blackduckFixPrParamSection);
        }
    }
}

function handlePostMergeWorkflowSectionsVisibility() {
    var selectedOption = securityProduct.value;
    var blackduckscaWaitForScanEnabled = document.querySelector('input[name="_.blackducksca_waitForScan"]').checked;
    var polarisWaitForScanEnabled = document.querySelector('input[name="_.polaris_waitForScan"]').checked;
    var coverityWaitForScanEnabled = document.querySelector('input[name="_.coverity_waitForScan"]').checked;

    if (selectedOption === 'blackducksca') {
        var blackduckSCASarif_section = document.getElementById('blackducksca_sarif_report_sec');
        var blackduckSCAPRComment_section = document.getElementById('blackducksca_pr_comment_sec');
        var blackduckSCAFixPr_section = document.getElementById('blackducksca_fixPr_sec');
        if (blackduckscaWaitForScanEnabled == false) {
            hideParticularDiv(blackduckSCASarif_section);
            hideParticularDiv(blackduckSCAPRComment_section);
            hideParticularDiv(blackduckSCAFixPr_section);
            clearInputFields(blackduckSCASarif_section);
            clearInputFields(blackduckSCAPRComment_section);
            clearInputFields(blackduckSCAFixPr_section);
        } else if (blackduckscaWaitForScanEnabled == true) {
            showParticularDiv(blackduckSCASarif_section);
            showParticularDiv(blackduckSCAPRComment_section);
            showParticularDiv(blackduckSCAFixPr_section);
        }
    } else if (selectedOption === 'polaris') {
        var polarisSarif_section = document.getElementById('polaris_sarif_report_sec');
        var polarisPRComment_section = document.getElementById('polaris_pr_comment_sec');
        if (polarisWaitForScanEnabled == false) {
            hideParticularDiv(polarisSarif_section);
            hideParticularDiv(polarisPRComment_section);
            clearInputFields(polarisSarif_section);
            clearInputFields(polarisPRComment_section);
        } else if (polarisWaitForScanEnabled == true) {
            showParticularDiv(polarisSarif_section);
            showParticularDiv(polarisPRComment_section);
        }
    } else if (selectedOption === 'coverity') {
        var coverityPRComment_section = document.getElementById('coverity_pr_comment_sec');
        if (coverityWaitForScanEnabled == false) {
            hideParticularDiv(coverityPRComment_section);
            clearInputFields(coverityPRComment_section);
        } else if (coverityWaitForScanEnabled == true) {
            showParticularDiv(coverityPRComment_section);
        }
    }

}