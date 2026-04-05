import {listSessions} from "./api.js";

const sessionTable = document.getElementById('session-table');

export async function loadSessions() {
    const sessions = await listSessions();
    populateSessions(sessions);
}

export function populateSessions(sessions) {
    const tbody = sessionTable.querySelector('tbody');
    tbody.innerHTML = '';

    Object.entries(sessions).forEach(([id, session]) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${session.user_info.email}</td>
            <td>${session.lastSeen}</td>
        `;
        tbody.appendChild(row);
    });
}