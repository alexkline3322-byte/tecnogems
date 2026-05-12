function copyCode(code, id) {
  navigator.clipboard.writeText(code).then(function() {
    var btn = document.querySelector('[onclick*="copyCode(\\\'' + code + '\\\'"]');
    if (btn) { btn.innerHTML = '\u2713'; setTimeout(function(){ btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'; }, 1500); }
  });
}
function filterOrders(filter, btn) {
  document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  var cards = document.querySelectorAll('.order-card');
  var visible = 0;
  cards.forEach(function(card) {
    var s = card.dataset.status;
    var show = filter === 'all' || s === filter || (filter === 'processing' && (s === 'processing' || s === 'supplier_pending'));
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  var noMsg = document.getElementById('no-orders-msg');
  if (noMsg) noMsg.style.display = visible === 0 ? '' : 'none';
}
