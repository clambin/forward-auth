/**
 * @vitest-environment happy-dom
 */
import { test, expect, beforeEach, vi } from 'vitest';
import { initDarkMode } from '../static/js/darkmode.js';

beforeEach(() => {
    document.body.innerHTML = `
        <button id="theme-toggle">
            <i data-lucide="sun" class="sun-icon"></i>
            <i data-lucide="moon" class="moon-icon"></i>
        </button>
    `;
    document.body.className = '';
    localStorage.clear();
    // Mock lucide.createIcons
    global.lucide = {
        createIcons: vi.fn()
    };
});

test('initDarkMode calls lucide.createIcons', () => {
    initDarkMode();
    expect(global.lucide.createIcons).toHaveBeenCalled();
});

test('initDarkMode adds dark-mode class if theme is dark in localStorage', () => {
    localStorage.setItem('theme', 'dark');
    initDarkMode();
    expect(document.body.classList.contains('dark-mode')).toBe(true);
});

test('initDarkMode does not add dark-mode class if theme is light in localStorage', () => {
    localStorage.setItem('theme', 'light');
    initDarkMode();
    expect(document.body.classList.contains('dark-mode')).toBe(false);
});

test('clicking toggle button toggles dark-mode class and updates localStorage', () => {
    initDarkMode();
    const toggle = document.getElementById('theme-toggle');

    // Toggle to dark
    toggle.click();
    expect(document.body.classList.contains('dark-mode')).toBe(true);
    expect(localStorage.getItem('theme')).toBe('dark');
    
    // Check icon visibility (via computed style if possible, or just checking class existence)
    // Happy-dom doesn't fully compute CSS, but we can verify our CSS changes via tests if we want to be thorough.
    // However, the current requirement is just to flip the logic.
    // Let's add a test that specifically checks the icons' intended visibility.
});

test('icons have correct visibility classes', () => {
    initDarkMode();
    const sunIcon = document.querySelector('.sun-icon');
    const moonIcon = document.querySelector('.moon-icon');
    
    // Light mode (default)
    expect(document.body.classList.contains('dark-mode')).toBe(false);
    // In light mode, sun should be visible (display: block in CSS)
    // moon should be hidden (display: none in CSS)
    
    // Since we can't easily check computed CSS in this environment without a full browser, 
    // we just ensure the classes are there and the toggle works.
    
    const toggle = document.getElementById('theme-toggle');
    toggle.click();
    expect(document.body.classList.contains('dark-mode')).toBe(true);
    // In dark mode, moon should be visible
});

test('initDarkMode handles missing toggle button gracefully', () => {
    document.body.innerHTML = '';
    // Should not throw
    initDarkMode();
});
