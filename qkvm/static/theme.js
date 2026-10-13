// Runs before the first paint so the page never flashes the wrong theme.
(function () {
  var pref = 'auto';
  try { pref = localStorage.getItem('qkvm.theme') || 'auto'; } catch (e) { /* storage blocked */ }
  if (pref !== 'light' && pref !== 'dark') pref = 'auto';
  var dark = pref === 'dark' || (pref === 'auto' && !matchMedia('(prefers-color-scheme: light)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.dataset.themePref = pref;  // picks which icon the theme toggle shows
})();
