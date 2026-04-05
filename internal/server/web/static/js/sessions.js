import {listSessions, deleteSession} from "./api.js";

export let sessionTable = typeof document !== 'undefined' ? document.getElementById('session-table') : null;
export let selectAllCheckbox = typeof document !== 'undefined' ? document.getElementById('select-all') : null;
export let deleteSelectedButton = typeof document !== 'undefined' ? document.getElementById('delete-selected') : null;

export function setSessionTable(el) { sessionTable = el; }
export function setSelectAllCheckbox(el) { selectAllCheckbox = el; }
export function setDeleteSelectedButton(el) { deleteSelectedButton = el; }

if (selectAllCheckbox) {
    selectAllCheckbox.addEventListener('change', (e) => {
        const rowCheckboxes = sessionTable.querySelectorAll('tbody input[type="checkbox"]');
        rowCheckboxes.forEach(cb => cb.checked = e.target.checked);
    });
}

if (deleteSelectedButton) {
    deleteSelectedButton.addEventListener('click', async () => {
        const selectedCheckboxes = sessionTable.querySelectorAll('tbody input[type="checkbox"]:checked');
        const ids = Array.from(selectedCheckboxes).map(cb => cb.closest('tr').dataset.sessionId);
        
        if (ids.length === 0) {
            return;
        }

        if (confirm(`Are you sure you want to delete ${ids.length} session(s)?`)) {
            for (const id of ids) {
                try {
                    await deleteSession(id);
                } catch (e) {
                    console.error(`Failed to delete session ${id}:`, e);
                }
            }
            await loadSessions();
        }
    });
}

export async function loadSessions() {
    const sessions = await listSessions();
    populateSessions(sessions);
}

export function populateSessions(sessions) {
    if (!sessionTable) return;
    const tbody = sessionTable.querySelector('tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = false;
    }

    Object.entries(sessions).forEach(([id, session]) => {
        const row = (typeof document !== 'undefined' ? document : sessionTable.ownerDocument).createElement('tr');
        row.dataset.sessionId = id;
        const lastSeen = new Date(session.last_seen).toLocaleString();
        row.innerHTML = `
            <td><input type="checkbox" class="session-select"/></td>
            <td>${session.user_info.email}</td>
            <td>${lastSeen}</td>
        `;
        tbody.appendChild(row);
    });
}