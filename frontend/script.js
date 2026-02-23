let currentRules = [];

function addRule(type) {
    let value;
    if (type === 'ip') value = document.getElementById('ruleIP').value;
    else if (type === 'app') value = document.getElementById('ruleApp').value;
    else if (type === 'domain') value = document.getElementById('ruleDomain').value;
    if (!value) return;
    currentRules.push({ type, value });
    alert(`Added rule: ${type} - ${value}`);
}

async function analyze() {
    const fileInput = document.getElementById('pcapFile');
    if (!fileInput.files[0]) {
        alert('Please select a PCAP file');
        return;
    }
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    const requestBody = { rules: currentRules };
    formData.append('request', new Blob([JSON.stringify(requestBody)], {type: 'application/json'}));

    const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        body: formData
    });
    const result = await response.json();
    displayResults(result);
}

function displayResults(result) {
    const div = document.getElementById('results');
    div.innerHTML = `
        <h2>Results</h2>
        <p>Total packets: ${result.total_packets}</p>
        <p>Forwarded: ${result.forwarded}</p>
        <p>Dropped: ${result.dropped}</p>
        <h3>Application Breakdown</h3>
        <ul>
            ${Object.entries(result.app_breakdown).map(([app, count]) => `<li>${app}: ${count}</li>`).join('')}
        </ul>
        <p>Output file: <a href="/download/${result.output_file}">Download</a> (Note: download endpoint not implemented)</p>
    `;
}