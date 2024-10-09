function showProductType(sectionId) {
    // Hide all sections
    var sections = document.querySelectorAll('.product-type-section');
    sections.forEach(function (section) {
        section.style.display = 'none';
    });

    // Show the selected section
    var scanTypeSection = document.getElementById(sectionId);
    if (scanTypeSection) {
        scanTypeSection.style.display = "block";
    }

    // Highlight the selected tab
    var tabs = document.querySelectorAll('.scan-tab-box');
    tabs.forEach(function (tab) {
        tab.style.backgroundColor = '';
    });

    var selectedTab = document.querySelector('.tab-container-box [onclick*="' + sectionId + '"]');
    if (selectedTab) {
        selectedTab.style.backgroundColor = '#f1f1f1';
    }
}

function showOSType(sectionId) {
    // Hide all sections
    var sections = document.querySelectorAll('.os-section');
    sections.forEach(function (section) {
        section.style.display = 'none';
    });

    // Show the selected section
    var scanTypeSection = document.getElementById(sectionId);
    if (scanTypeSection) {
        scanTypeSection.style.display = "block";
    }

    // Highlight the selected tab
    var tabs = document.querySelectorAll('.os-tab-box');
    tabs.forEach(function (tab) {
        tab.style.backgroundColor = '';
    });

    var selectedTab = document.querySelector('.tab-container-box [onclick*="' + sectionId + '"]');
    if (selectedTab) {
        selectedTab.style.backgroundColor = '#f1f1f1';
    }
}

// Function to clear all input fields except those with a specific class
function clearAllTabFieldsAndTestConnectionMessages(sectionId) {
    // Clear tab fields
    var tabSection = document.getElementById(sectionId);
    if (tabSection) {
        var inputFields = tabSection.querySelectorAll("input, select");
        inputFields.forEach(function (inputField) {
            inputField.value = "";
        });

        var okElement = tabSection.querySelector('.ok');
        if (okElement) {
            okElement.remove();
        }

        var errorElement = tabSection.querySelector('.error');
        if (errorElement) {
            errorElement.remove();
        }
    }
}

// Function to check for existing values and display related boxes on page load
function checkExistingFieldValues() {
    let blackDuckSCAUrl = document.querySelector("input[name='blackDuckSCAUrl']").value;
    let coverityConnectUrl = document.querySelector("input[name='coverityConnectUrl']").value;
    let polarisServerUrl = document.querySelector("input[name='polarisServerUrl']").value;
    let srmUrl = document.querySelector("input[name='srmUrl']").value;

    let bridgeCliDownloadUrlForWindows = document.querySelector("input[name='bridgeDownloadUrlForWindows']").value;
    let bridgeCliDownloadUrlForLinux = document.querySelector("input[name='bridgeDownloadUrlForLinux']").value;
    let bridgeCliDownloadUrlForMac = document.querySelector("input[name='bridgeDownloadUrlForMac']").value;

    // Check the values of blackDuckSCAUrl, coverityConnectUrl, and polarisServerUrl
    // and select the appropriate scan type based on their values
    if (blackDuckSCAUrl) {
        showProductType("blackducksca-section"); // Show Black Duck SCA box if there is a value
    } else if (coverityConnectUrl) {
        showProductType("coverity-section"); // Show Coverity box if there is a value
    } else if (polarisServerUrl) {
        showProductType("polaris-section"); // Show Polaris box if there is a value
    } else if (srmUrl) {
        showProductType("srm-section"); // Show Polaris box if there is a value
    } else {
        // If none of the URLs have a value, default to Black Duck SCA
        showProductType("blackducksca-section");
    }

    // Check the values of bridgeDownloadUrlForMac, bridgeDownloadUrlForLinux, and bridgeDownloadUrlForWindows
    // and select the appropriate OS type based on their values
    if (bridgeCliDownloadUrlForMac) {
        showOSType("mac-section");
    } else if (bridgeCliDownloadUrlForLinux) {
        showOSType("linux-section");
    } else if (bridgeCliDownloadUrlForWindows) {
        showOSType("windows-section");
    } else {
        console.log("here")
        // If none of the URLs have a value, default to MAC
        showOSType("mac-section");
    }
}


// window.addEventListener("load", checkExistingFieldValues);

window.addEventListener("load", function() {
    // Add an event listener to call the checkExistingFieldValues function on page load
    checkExistingFieldValues();

    // Add event listeners for the tabs
    document.getElementById('blackduck-tab').addEventListener('click', function() {
        showProductType('blackducksca-section');
    });

    document.getElementById('coverity-tab').addEventListener('click', function() {
        showProductType('coverity-section');
    });

    document.getElementById('polaris-tab').addEventListener('click', function() {
        showProductType('polaris-section');
    });

    document.getElementById('srm-tab').addEventListener('click', function() {
        showProductType('srm-section');
    });

    // Add event listeners for OS tabs
    document.getElementById('mac-tab').addEventListener('click', function() {
        showOSType('mac-section');
    });

    document.getElementById('linux-tab').addEventListener('click', function() {
        showOSType('linux-section');
    });

    document.getElementById('windows-tab').addEventListener('click', function() {
        showOSType('windows-section');
    });

    // Add event listeners for the Clear buttons
    document.getElementById('clear-blackduck').addEventListener('click', function() {
        clearAllTabFieldsAndTestConnectionMessages('blackducksca-section');
    });

    document.getElementById('clear-coverity').addEventListener('click', function() {
        clearAllTabFieldsAndTestConnectionMessages('coverity-section');
    });

    document.getElementById('clear-polaris').addEventListener('click', function() {
        clearAllTabFieldsAndTestConnectionMessages('polaris-section');
    });

    document.getElementById('clear-srm').addEventListener('click', function() {
        clearAllTabFieldsAndTestConnectionMessages('srm-section');
    });
});
