(function(){
  const search = document.getElementById('gameSearch');
  const rows = Array.from(document.querySelectorAll('.admin-game-row'));
  const counter = document.getElementById('gameCounter');
  let mode = 'active';

  function normalize(s){ return (s || '').toLowerCase().trim(); }

  function render(){
    const q = normalize(search.value);
    let visible = 0;

    rows.forEach(row => {
      const input = row.querySelector('input[type="checkbox"][name="active_game"]');
      const isActive = row.classList.contains('is-active') || (input && input.checked);
      const hay = normalize(row.dataset.gameName);
      let show = false;

      if (q.length > 0) {
        show = hay.includes(q);
      } else if (mode === 'all') {
        show = true;
      } else {
        show = isActive;
      }

      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    if (q.length > 0) {
      counter.textContent = '\u0646\u062a\u0627\u0626\u062c \u0627\u0644\u0628\u062d\u062b: ' + visible;
    } else if (mode === 'all') {
      counter.textContent = '\u064a\u062a\u0645 \u0639\u0631\u0636 \u062c\u0645\u064a\u0639 \u0627\u0644\u0623\u0644\u0639\u0627\u0628: ' + visible;
    } else {
      counter.textContent = '\u064a\u062a\u0645 \u0639\u0631\u0636 \u0627\u0644\u0623\u0644\u0639\u0627\u0628 \u0627\u0644\u0645\u0641\u0639\u0651\u0644\u0629 \u0641\u0642\u0637: ' + visible + '. \u0627\u0643\u062a\u0628 \u0641\u064a \u0627\u0644\u0628\u062d\u062b \u0644\u0625\u0638\u0647\u0627\u0631 \u0644\u0639\u0628\u0629 \u063a\u064a\u0631 \u0645\u0641\u0639\u0651\u0644\u0629.';
    }
  }

  search.addEventListener('input', render);
  document.getElementById('showAllGames').addEventListener('click', () => {
    mode = 'all';
    search.value = '';
    render();
  });
  document.getElementById('hideInactiveGames').addEventListener('click', () => {
    mode = 'active';
    search.value = '';
    render();
  });
  rows.forEach(row => {
    const input = row.querySelector('input[type="checkbox"][name="active_game"]');
    if (input) {
      input.addEventListener('change', () => {
        row.classList.toggle('is-active', input.checked);
        render();
      });
    }
  });

  render();
})();
