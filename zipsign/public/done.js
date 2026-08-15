const parts = window.location.pathname.split('/').filter(Boolean);
const id = parts.length > 1 ? parts[1] : null;

(async function load() {
  if (!id) return;
  try {
    const res = await fetch(`/api/packages/${id}`);
    if (!res.ok) return;
    const pkg = await res.json();
    document.getElementById('pkgLine').textContent =
      `${pkg.originalName} was signed and stored.`;
  } catch {}
})();
