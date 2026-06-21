/**
 * Syntex Solutions — Main Application JS
 * v2.4.1 | See /js/config.js for API config
 */

document.addEventListener('DOMContentLoaded', function () {

    const params = new URLSearchParams(window.location.search);

    // VULNERABILITY: DOM XSS — URL params written directly to innerHTML
    // Payload: /?message=<img src=x onerror=alert(1)>
    const msg = params.get('message');
    if (msg) {
        const el = document.getElementById('flash-message');
        if (el) el.innerHTML = decodeURIComponent(msg);
    }

    const err = params.get('error');
    if (err) {
        const el = document.getElementById('flash-error');
        if (el) el.innerHTML = decodeURIComponent(err);
    }

    // VULNERABILITY: DOM XSS via URL hash fragment
    // Payload: /dashboard#<img src=x onerror=alert(document.cookie)>
    const hash = window.location.hash.slice(1);
    if (hash && document.getElementById('content-section')) {
        document.getElementById('content-section').innerHTML = decodeURIComponent(hash);
    }

    // VULNERABILITY: DOM XSS in search preview — user input written to innerHTML
    const searchInput = document.getElementById('header-search');
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            const preview = document.getElementById('search-preview');
            if (preview) {
                // No encoding — attacker can inject via controlled search input
                preview.innerHTML = this.value.length > 0
                    ? 'Searching: <strong>' + this.value + '</strong>'
                    : '';
            }
        });
        searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                window.location.href = '/search?q=' + encodeURIComponent(this.value);
            }
        });
    }

    // Notification badge update
    const badge = document.querySelector('.badge-dot');
    if (badge) {
        fetch('/api/v1/users/me', {
            credentials: 'include',
            headers: { 'Authorization': 'Bearer ' + (window.SYNTEX_CONFIG?._debug_token || '') }
        })
        .then(r => r.json())
        .then(data => { /* update UI */ })
        .catch(() => {});
    }

    // Highlight active sidebar link
    const links = document.querySelectorAll('.sidebar-nav a');
    links.forEach(link => {
        if (window.location.pathname.startsWith(link.getAttribute('href'))) {
            link.classList.add('active');
        }
    });

    // Auto-dismiss flash alerts
    setTimeout(() => {
        document.querySelectorAll('.alert-auto-dismiss').forEach(el => {
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 300);
        });
    }, 5000);

});
