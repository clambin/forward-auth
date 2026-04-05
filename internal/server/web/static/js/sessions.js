import {listSessions} from "./api.js";

const sessionTable = document.getElementById('session-table');

export async function loadSessions() {
    const sessions = await listSessions();
    populateSessions(sessions);
}

export function populateSessions(sessions) {
    const tbody = sessionTable.querySelector('tbody');
    tbody.innerHTML = '';

    sessions.forEach(session => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${session.user}</td>
            <td>${session.lastSeen}</td>
        `;
        tbody.appendChild(row);
    });
}