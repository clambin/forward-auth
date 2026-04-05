import { test, assertEquals, assert } from './test_runner.js';
import { listSessions, deleteSession } from '../static/js/api.js';

// Mock fetch globally
global.fetch = async (url, options) => {
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
};

await test('listSessions fetches correctly', async () => {
    const sessions = await listSessions();
    assertEquals(Object.keys(sessions).length, 2);
    assertEquals(sessions.id1.user_info.email, "user1@example.com");
});

await test('deleteSession calls correct URL', async () => {
    // Should not throw
    await deleteSession('id1');
});

await test('deleteSession throws on failure', async () => {
    try {
        await deleteSession('fail');
        assert(false, "Should have thrown an error");
    } catch (e) {
        assert(e.message.includes('Failed to delete session fail'));
    }
});
