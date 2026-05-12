(function(){
  var input = document.getElementById('gameSearch');
  if (!input) return;
  var cards = Array.from(document.querySelectorAll('.searchable-game'));
  var names = cards.map(function(c){ return (c.getAttribute('data-name') || c.innerText || '').toLowerCase(); });
  input.addEventListener('input', function(){
    var q = this.value.trim().toLowerCase();
    var visible = 0;
    cards.forEach(function(card, i){
      var show = names[i].indexOf(q) >= 0;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    var noMsg = document.getElementById('no-games-msg');
    if (noMsg) noMsg.style.display = visible === 0 && q ? '' : 'none';
  });
})();

// Back to top
(function(){
  var btn = document.getElementById('back-to-top');
  if (!btn) return;
  window.addEventListener('scroll', function(){
    btn.classList.toggle('visible', window.scrollY > 400);
  });
  btn.addEventListener('click', function(){
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
})();
