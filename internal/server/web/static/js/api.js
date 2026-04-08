export async function listSessions() {
    const r = await fetch('/api/v1/sessions/list');
    if (!r.ok) {
        throw new Error('Failed to fetch sessions');
    }
    return await r.json();
}

export async function deleteSession(id) {
    const r = await fetch(`/api/v1/sessions/session/${id}`, {
        method: 'DELETE',
    });
    if (!r.ok) {
        throw new Error(`Failed to delete session ${id}`);
    }
}
