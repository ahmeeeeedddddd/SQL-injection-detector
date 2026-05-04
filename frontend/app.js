const scanInput = document.getElementById('scanInput');
const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const loadingState = document.getElementById('loadingState');
const resultContainer = document.getElementById('resultContainer');
const historyCount = document.getElementById('historyCount');

let scanCounter = 0;

scanBtn.onclick = async () => {
    const text = scanInput.value;
    if (!text.trim()) return alert("Analysis failed: input buffer empty.");

    // Loading transition
    scanBtn.disabled = true;
    loadingState.classList.remove('hidden');
    resultContainer.innerHTML = '';

    try {
        const response = await fetch('http://localhost:8000/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input: text })
        });

        if (response.ok) {
            const data = await response.json();
            renderResult(data);
            saveToHistory(text, data.verdict);
            scanCounter++;
            historyCount.innerText = `${scanCounter} SESSION ENTRIES`;
        } else {
            console.error("Server returned error:", response.status);
            alert("Network anomaly detected. Ensure backend is running.");
        }
    } catch (err) {
        console.error("Fetch error:", err);
        alert("Connectivity error. Check API status.");
    } finally {
        scanBtn.disabled = false;
        loadingState.classList.add('hidden');
    }
};

clearBtn.onclick = () => {
    scanInput.value = '';
    resultContainer.innerHTML = '';
};

function renderResult(data) {
    const verdictLower = data.verdict.toLowerCase();
    const highlightClass = `highlight-${verdictLower}`;
    
    resultContainer.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <div class="verdict-badge ${verdictLower}">
                    <svg class="verdict-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        ${verdictLower === 'safe' 
                            ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
                            : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
                    </svg>
                    ${data.verdict}
                </div>
            </div>
            
            <div class="result-grid">
                <div class="result-cell">
                    <div class="cell-label">Risk Score</div>
                    <div class="cell-value ${highlightClass}">${(data.score * 100).toFixed(0)}%</div>
                    <div class="score-bar" style="margin-top: 8px;">
                        <div class="score-bar-fill ${verdictLower}" style="width: ${data.score * 100}%; background: var(--${verdictLower === 'safe' ? 'accent' : verdictLower === 'suspicious' ? 'warn' : 'danger'})"></div>
                    </div>
                </div>
                <div class="result-cell">
                    <div class="cell-label">Attack Vector</div>
                    <div class="cell-value">${data.attack_type.toUpperCase()}</div>
                </div>
            </div>

            <div class="echo-section">
                <div class="echo-label">Payload Echo</div>
                <div class="echo-value">${escapeHtml(data.input)}</div>
            </div>
        </div>
    `;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
