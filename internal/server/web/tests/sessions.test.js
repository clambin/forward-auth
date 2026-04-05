import { test, assertEquals, assert } from './test_runner.js';
import { populateSessions, setSessionTable } from '../static/js/sessions.js';

// Mock DOM
const mockDocument = {
    ownerDocument: null,
    getElementById: (id) => {
        if (id === 'session-table') {
            return {
                ownerDocument: mockDocument,
                querySelector: (q) => {
                    if (q === 'tbody') {
                        return {
                            innerHTML: '',
                            appendChild: (child) => {
                                mockDocument.tbodyChildren.push(child);
                            }
                        }
                    }
                },
                querySelectorAll: (q) => []
            }
        }
        return null;
    },
    createElement: (tag) => {
        return {
            dataset: {},
            innerHTML: '',
            appendChild: (c) => {}
        }
    },
    tbodyChildren: []
};

await test('populateSessions renders correctly', async () => {
    mockDocument.tbodyChildren = [];
    setSessionTable(mockDocument.getElementById('session-table'));
    
    const sessions = {
        "id1": { user_info: { email: "user1@example.com" }, last_seen: "2024-01-01" },
        "id2": { user_info: { email: "user2@example.com" }, last_seen: "2024-01-02" }
    };
    
    populateSessions(sessions);
    
    assertEquals(mockDocument.tbodyChildren.length, 2);
    assertEquals(mockDocument.tbodyChildren[0].dataset.sessionId, "id1");
    assert(mockDocument.tbodyChildren[0].innerHTML.includes("user1@example.com"));
    assert(mockDocument.tbodyChildren[0].innerHTML.includes(new Date("2024-01-01").toLocaleString()));
    assertEquals(mockDocument.tbodyChildren[1].dataset.sessionId, "id2");
    assert(mockDocument.tbodyChildren[1].innerHTML.includes("user2@example.com"));
    assert(mockDocument.tbodyChildren[1].innerHTML.includes(new Date("2024-01-02").toLocaleString()));
});
