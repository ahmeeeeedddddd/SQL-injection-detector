function saveToHistory(input, verdict) {
    const historyList = document.getElementById('historyList');
    const li = document.createElement('li');
    li.style.padding = '10px 14px';
    li.style.borderBottom = '0.5px solid var(--border)';
    li.style.fontSize = '12px';
    li.style.display = 'flex';
    li.style.justifyContent = 'space-between';
    li.style.alignItems = 'center';

    const color = verdict.toLowerCase() === 'safe' ? 'var(--accent)' : (verdict.toLowerCase() === 'suspicious' ? 'var(--warn)' : 'var(--danger)');

    li.innerHTML = `
        <code style="color: var(--muted);">${input.length > 40 ? input.substring(0, 37) + '...' : input}</code>
        <span style="color: ${color}; font-weight: 700; font-size: 10px; text-transform: uppercase;">${verdict}</span>
    `;
    historyList.prepend(li); 
}