// Applies the theme chosen in the console (src/prefs.ts) before the first paint. Loaded as its own file because the
// content security policy allows no inline script. Reads one key and accepts only two words.
try {
  var chosen = window.localStorage.getItem("lynceus.theme");
  if (chosen === "dark" || chosen === "light") document.documentElement.setAttribute("data-theme", chosen);
} catch (e) {
  // storage refused: the console follows the system setting
}
