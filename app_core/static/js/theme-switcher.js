(function () {
  "use strict";

  var STORAGE_KEY = "nics-cyberlab-theme";
  var DEFAULT_THEME = "dark";

  var THEMES = [
    { id: "dark", label: "Dark", hint: "Default SOC", colors: ["#22d3ee", "#38bdf8"] },
    { id: "light", label: "Light", hint: "High visibility", colors: ["#0284c7", "#2563eb"] },
    { id: "mixed", label: "Mixed", hint: "Twilight balance", colors: ["#38bdf8", "#a78bfa"] },
    { id: "blueteam", label: "Blue Team", hint: "Defensive", colors: ["#2dd4bf", "#0ea5e9"] },
    { id: "redteam", label: "Red Team", hint: "Offensive", colors: ["#ef4444", "#f59e0b"] }
  ];

  function getStoredTheme() {
    try {
      var stored = window.localStorage.getItem(STORAGE_KEY);
      if (stored && THEMES.some(function (t) { return t.id === stored; })) return stored;
    } catch (err) { /* localStorage unavailable */ }
    return DEFAULT_THEME;
  }

  function applyTheme(themeId) {
    document.documentElement.setAttribute("data-theme", themeId);
    try { window.localStorage.setItem(STORAGE_KEY, themeId); } catch (err) { /* ignore */ }
    document.dispatchEvent(new CustomEvent("themechange", { detail: { theme: themeId } }));
  }

  function setTheme(themeId) {
    if (!THEMES.some(function (t) { return t.id === themeId; })) return;
    applyTheme(themeId);
    document.querySelectorAll(".theme-switcher").forEach(refreshActiveState);
  }

  function refreshActiveState(root) {
    var current = document.documentElement.getAttribute("data-theme") || DEFAULT_THEME;
    root.querySelectorAll(".theme-switcher-option").forEach(function (opt) {
      opt.classList.toggle("is-active", opt.getAttribute("data-theme-id") === current);
    });
    var swatch = root.querySelector(".theme-switcher-trigger .theme-switcher-swatch");
    var label = root.querySelector(".theme-switcher-trigger-label");
    var theme = THEMES.find(function (t) { return t.id === current; });
    if (label && theme) label.textContent = theme.label;
    if (swatch && theme) {
      swatch.style.background = "linear-gradient(135deg," + theme.colors[0] + "," + theme.colors[1] + ")";
    }
  }

  function closeAll(except) {
    document.querySelectorAll(".theme-switcher.is-open").forEach(function (el) {
      if (el !== except) el.classList.remove("is-open");
    });
  }

  function buildWidget() {
    var root = document.createElement("div");
    root.className = "theme-switcher";

    var trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "theme-switcher-trigger";
    trigger.setAttribute("aria-haspopup", "true");
    trigger.setAttribute("aria-label", "Change visual theme");
    trigger.innerHTML =
      '<span class="theme-switcher-swatch"></span>' +
      '<span class="theme-switcher-trigger-label">Theme</span>';

    var menu = document.createElement("div");
    menu.className = "theme-switcher-menu";
    menu.setAttribute("role", "menu");

    THEMES.forEach(function (theme) {
      var opt = document.createElement("button");
      opt.type = "button";
      opt.className = "theme-switcher-option";
      opt.setAttribute("data-theme-id", theme.id);
      opt.setAttribute("role", "menuitem");
      opt.innerHTML =
        '<span class="theme-switcher-option-swatch" style="background:linear-gradient(135deg,' +
        theme.colors[0] + "," + theme.colors[1] + ')"></span>' +
        '<span>' + theme.label + '<br><small style="font-weight:500;opacity:.65;text-transform:none;letter-spacing:0;">' + theme.hint + '</small></span>';
      opt.addEventListener("click", function (ev) {
        ev.stopPropagation();
        setTheme(theme.id);
        root.classList.remove("is-open");
      });
      menu.appendChild(opt);
    });

    trigger.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var willOpen = !root.classList.contains("is-open");
      closeAll(root);
      root.classList.toggle("is-open", willOpen);
    });

    root.appendChild(trigger);
    root.appendChild(menu);
    refreshActiveState(root);
    return root;
  }

  function mount(target) {
    var widget = buildWidget();
    var container = typeof target === "string" ? document.querySelector(target) : target;
    if (container) {
      container.appendChild(widget);
    } else {
      widget.style.position = "fixed";
      widget.style.top = "1rem";
      widget.style.right = "1rem";
      widget.style.zIndex = "9999";
      document.body.appendChild(widget);
    }
    return widget;
  }

  document.addEventListener("click", function () { closeAll(); });
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") closeAll();
  });

  // Apply persisted/default theme immediately on script load (before DOM
  // ready) so the page never flashes the wrong palette.
  applyTheme(getStoredTheme());

  window.NicsThemeSwitcher = { THEMES: THEMES, mount: mount, setTheme: setTheme, getTheme: getStoredTheme };
})();
