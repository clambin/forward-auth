export async function listSessions() {
    const r = await fetch('/api/v1/sessions');
    if (!r.ok) {
        throw new Error('Failed to fetch sessions');
    }
    return await r.json();
}
