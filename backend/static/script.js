let currentRules = [];

function addRule(type) {
    let value = "";

    if (type === "ip") {
        value = document.getElementById("ruleIP").value.trim();
        document.getElementById("ruleIP").value = "";
    } else if (type === "app") {
        value = document.getElementById("ruleApp").value.trim();
        document.getElementById("ruleApp").value = "";
    } else if (type === "domain") {
        value = document.getElementById("ruleDomain").value.trim();
        document.getElementById("ruleDomain").value = "";
    }

    if (!value) {
        alert("Enter value first");
        return;
    }

    currentRules.push({ type: type, value: value });
    alert("Rule added: " + type + " = " + value);
}

async function analyze() {
    const fileInput = document.getElementById("pcapFile");

    if (!fileInput.files.length) {
        alert("Select PCAP file");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("rules", JSON.stringify(currentRules));

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            body: formData
        });

        const result = await response.json();
        displayResults(result);

    } catch (error) {
        console.error(error);
        alert("Analysis failed");
    }
}

function displayResults(result) {
    const div = document.getElementById("results");

    let html = `
        <h2>Results</h2>
        <p><strong>Job ID:</strong> ${result.job_id}</p>
        <p><strong>Total packets:</strong> ${result.total_packets}</p>
        <p><strong>Forwarded:</strong> ${result.forwarded}</p>
        <p><strong>Dropped:</strong> ${result.dropped}</p>
        <h3>Application Breakdown</h3>
        <ul>
    `;

    for (const app in result.app_breakdown) {
        html += `<li>${app}: ${result.app_breakdown[app]}</li>`;
    }

    html += `</ul>`;

    div.innerHTML = html;
}