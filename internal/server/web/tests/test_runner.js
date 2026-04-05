/**
 * Simple test runner for JS
 */
export function assert(condition, message) {
    if (!condition) {
        throw new Error(message || "Assertion failed");
    }
}

export function assertEquals(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message || "Assertion failed"}: expected ${expected}, but got ${actual}`);
    }
}

export async function test(name, fn) {
    try {
        await fn();
        console.log(`✅ ${name}`);
    } catch (e) {
        console.error(`❌ ${name}`);
        console.error(e);
        process.exit(1);
    }
}
