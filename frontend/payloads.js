const examplePayloads = [
    "' OR 1=1 --", 
    "1 UNION SELECT username, password FROM users",
    "'; SELECT SLEEP(5)--",
    "1; DROP TABLE users"
];

const presetContainer = document.getElementById('payloadPresets');
examplePayloads.forEach(payload => {
    const btn = document.createElement('button');
    btn.innerText = payload;
    btn.className = 'ex-chip';
    btn.onclick = () => {
        document.getElementById('scanInput').value = payload;
    };
    presetContainer.appendChild(btn);
});