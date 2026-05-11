// TecnoGems V44 — app.js
// Disable submit button briefly on submit. Restore automatically so users
// never get stuck on "جارٍ المعالجة..." after a server-side validation error
// or when the browser restores the page from bfcache (back/forward cache).
document.addEventListener('submit', function (e) {
  var btn = e.target.querySelector('button[type="submit"]');
  if (btn && !btn.dataset.keep) {
    if (!btn.dataset._origText) btn.dataset._origText = btn.innerText;
    btn.disabled = true;
    var loadingText = btn.getAttribute('data-loading') || 'جارٍ المعالجة...';
    btn.innerText = loadingText;
    // Safety: if the navigation never happens (validation error reload, slow
    // network, server returns inline) re-enable after 12s so the UI is never
    // permanently stuck.
    setTimeout(function () {
      try {
        btn.disabled = false;
        if (btn.dataset._origText) btn.innerText = btn.dataset._origText;
      } catch (e) {}
    }, 12000);
  }
});

// Reset all submit buttons whenever the page is shown (covers bfcache restore
// after the browser navigates back, and also covers re-render after the
// server returns the same form with a flashed error).
function _tgResetSubmits() {
  document.querySelectorAll('button[type="submit"]').forEach(function (b) {
    b.disabled = false;
    if (b.dataset._origText) {
      b.innerText = b.dataset._origText;
    }
  });
}
window.addEventListener('pageshow', _tgResetSubmits);
document.addEventListener('DOMContentLoaded', _tgResetSubmits);

// Auto-dismiss flash alerts with close button
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.alert').forEach(function (el) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'alert-close';
    btn.innerHTML = '×';
    btn.onclick = function () { el.style.opacity = '0'; setTimeout(function () { el.remove(); }, 400); };
    el.appendChild(btn);
    setTimeout(function () {
      el.style.transition = 'opacity .4s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 400);
    }, 6000);
  });
});

// Faster game search using data-name attribute
(function () {
  var input = document.getElementById('gameSearch');
  if (!input) return;
  var cards = Array.from(document.querySelectorAll('.searchable-game'));
  var names = cards.map(function (c) {
    return (c.getAttribute('data-name') || c.innerText || '').toLowerCase();
  });
  input.addEventListener('input', function () {
    var q = this.value.trim().toLowerCase();
    var visible = 0;
    cards.forEach(function (card, i) {
      var show = !q || names[i].indexOf(q) >= 0;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    var noMsg = document.getElementById('no-games-msg');
    if (noMsg) noMsg.style.display = visible === 0 && q ? '' : 'none';
  });
})();
