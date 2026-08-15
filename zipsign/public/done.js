const parts = window.location.pathname.split('/').filter(Boolean);
const id = parts.length > 1 ? parts[1] : null;

(async function load() {
  if (!id) {
    document.getElementById('loadHint').hidden = true;
    return;
  }

  const link = document.getElementById('verifyLink');
  const copy = document.getElementById('copyLink');
  const card = document.getElementById('pkgCard');
  try {
    const res = await fetch(`/api/packages/${id}`);
    if (!res.ok) throw new Error();
    const pkg = await res.json();
    document.getElementById('pkgLine').textContent =
      `${pkg.originalName} was signed and stored.`;
    link.href = pkg.verifyUrl;
    link.textContent = pkg.verifyUrl;
    link.hidden = false;
    copy.hidden = false;
    document.getElementById('shareHint').hidden = false;
    copy.onclick = () => {
      navigator.clipboard.writeText(pkg.verifyUrl).then(() => {
        copy.textContent = 'Copied';
        setTimeout(() => (copy.textContent = 'Copy'), 1200);
      });
    };
    card.hidden = false;
  } catch {
    card.hidden = true;
  } finally {
    document.getElementById('loadHint').hidden = true;
  }
})();
