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
        var inputFields = div.querySelectorAll('input[type="text"], input[type="checkbox"]');
        inputFields.forEach(function (field) {
            if (field.type === 'text') {
                field.value = '';
            } else if (field.type === 'checkbox') {
                field.checked = false;
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

function setCheckboxToDefaultTrue(names) {
    names.forEach(function (name) {
        var checkbox = document.getElementsByName(name);
        if (checkbox && checkbox.length > 0) {
            checkbox[0].checked = true;
        }
    });
}

securityProduct.addEventListener('change', function () {
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

document.addEventListener('change', function () {
    var polarisAssessmentModeOption = document.querySelector('select[name="_.polaris_assessment_mode"]')?.value;
    var sourceUploadDiv = document.getElementById('source_upload');

    if (polarisAssessmentModeOption === 'SOURCE_UPLOAD') {
        showParticularDiv(sourceUploadDiv);
    }

    if (polarisAssessmentModeOption === 'CI' || polarisAssessmentModeOption === '') {
        clearInputFields(sourceUploadDiv);
        hideParticularDiv(sourceUploadDiv);
    }
});