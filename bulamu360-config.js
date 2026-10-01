// Bulamu360 backend configuration.
// Live site: same server that served the page (works on bulamu360.bybreyer.com and onrender.com).
// Opened as a local file: fall back to the Render backend.
window.BULAMU_API_BASE = window.BULAMU_API_BASE || (/^https?:$/.test(location.protocol) ? '' : 'https://bulamu360-backend.onrender.com');
