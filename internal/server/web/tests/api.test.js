import { test, expect, vi } from 'vitest';
import { listSessions, deleteSession } from '../static/js/api.js';

// Mock fetch globally
global.fetch = vi.fn(async (url, options) => {
    if (url === '/api/v1/sessions') {
        return {
            ok: true,
            json: async () => ({
                "id1": { user_info: { email: "user1@example.com" }, last_seen: "2024-01-01" },
                "id2": { user_info: { email: "user2@example.com" }, last_seen: "2024-01-02" }
            })
        };
    }
    if (url.startsWith('/api/v1/session/')) {
        const id = url.split('/').pop();
        if (id === 'fail') {
            return { ok: false };
        }
        return { ok: true };
    }
    return { ok: false };
});

test('listSessions fetches correctly', async () => {
    const sessions = await listSessions();
    expect(Object.keys(sessions).length).toBe(2);
    expect(sessions.id1.user_info.email).toBe("user1@example.com");
});

test('deleteSession calls correct URL', async () => {
    // Should not throw
    await deleteSession('id1');
    expect(global.fetch).toHaveBeenCalledWith('/api/v1/session/id1', expect.any(Object));
});

test('deleteSession throws on failure', async () => {
    await expect(deleteSession('fail')).rejects.toThrow('Failed to delete session fail');
});
