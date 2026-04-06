/**
 * @vitest-environment happy-dom
 */
import { test, expect, beforeEach, vi } from 'vitest';
import { loadSessions, setSessionTable } from '../static/js/sessions.js';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
    document.body.innerHTML = `
        <table id="session-table">
            <thead>
                <tr><th><input type="checkbox" id="select-all"/></th></tr>
            </thead>
            <tbody></tbody>
        </table>
    `;
    setSessionTable(document.getElementById('session-table'));
    vi.clearAllMocks();
});

test('loadSessions renders correctly', async () => {
    const sessions = {
        "id1": { user_info: { email: "user1@example.com" }, last_seen: "2024-01-01" },
        "id2": { user_info: { email: "user2@example.com" }, last_seen: "2024-01-02" }
    };
    
    global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => sessions
    });

    await loadSessions();
    
    const rows = document.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    expect(rows[0].dataset.sessionId).toBe("id1");
    expect(rows[0].innerHTML).toContain("user1@example.com");
    expect(rows[0].innerHTML).toContain(new Date("2024-01-01").toLocaleString());
    expect(rows[1].dataset.sessionId).toBe("id2");
    expect(rows[1].innerHTML).toContain("user2@example.com");
    expect(rows[1].innerHTML).toContain(new Date("2024-01-02").toLocaleString());
});
