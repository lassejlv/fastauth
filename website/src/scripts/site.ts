const root = document.documentElement;
const media = matchMedia("(prefers-color-scheme: dark)");

function applyTheme(theme: "light" | "dark") {
  root.dataset.theme = theme;
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-theme-toggle]")) {
    button.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }
}

applyTheme(root.dataset.theme === "dark" ? "dark" : "light");

if (!/Mac|iPhone|iPad/.test(navigator.platform)) {
  document.querySelectorAll("[data-mod-k]").forEach((kbd) => (kbd.textContent = "Ctrl K"));
}

media.addEventListener("change", (event) => {
  if (!localStorage.getItem("theme")) applyTheme(event.matches ? "dark" : "light");
});

document.addEventListener("click", (event) => {
  const target = event.target as HTMLElement;

  if (target.closest("[data-theme-toggle]")) {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    if ((next === "dark") === media.matches) localStorage.removeItem("theme");
    else localStorage.setItem("theme", next);
    applyTheme(next);
    return;
  }

  const copy = target.closest<HTMLButtonElement>("[data-copy]");
  if (copy) {
    const text =
      copy.dataset.copy ||
      Array.from(copy.closest("figure, .install")?.querySelectorAll(".line") ?? [], (line) => line.textContent ?? "").join("\n");
    navigator.clipboard.writeText(text).then(() => {
      const label = copy.dataset.label ?? copy.textContent ?? "Copy";
      copy.dataset.label = label;
      copy.textContent = "Copied";
      window.setTimeout(() => (copy.textContent = label), 1500);
    });
  }
});

const sidebar = document.querySelector<HTMLElement>(".sidebar");
const currentLink = sidebar?.querySelector<HTMLElement>("[aria-current='page']");
if (sidebar && currentLink) {
  const link = currentLink.getBoundingClientRect();
  const pane = sidebar.getBoundingClientRect();
  if (link.top < pane.top || link.bottom > pane.bottom) sidebar.scrollTop += link.top - pane.top - (pane.height - link.height) / 2;
}

const sheet = document.querySelector<HTMLDialogElement>("#nav-sheet");
if (sheet) {
  document.querySelectorAll("[data-nav-open]").forEach((b) =>
    b.addEventListener("click", () => {
      sheet.showModal();
      sheet.querySelector("[aria-current='page']")?.scrollIntoView({ block: "center" });
    }),
  );
  sheet.querySelectorAll("[data-nav-close]").forEach((b) => b.addEventListener("click", () => sheet.close()));
  sheet.addEventListener("click", (event) => {
    if (event.target === sheet) sheet.close();
  });
}

const outlineLinks = Array.from(document.querySelectorAll<HTMLAnchorElement>(".outline a[href^='#']"));
if (outlineLinks.length) {
  const headings = outlineLinks
    .map((link) => document.getElementById(decodeURIComponent(link.hash.slice(1))))
    .filter((h): h is HTMLElement => Boolean(h));
  const setActive = () => {
    const offset = 96;
    let current = headings[0];
    for (const heading of headings) {
      if (heading.getBoundingClientRect().top - offset <= 0) current = heading;
      else break;
    }
    if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 2) current = headings[headings.length - 1];
    for (const link of outlineLinks) {
      const active = current && link.hash === "#" + current.id;
      link.classList.toggle("active", Boolean(active));
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    }
  };
  let frame = 0;
  window.addEventListener("scroll", () => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(setActive);
  }, { passive: true });
  setActive();
}

document.querySelectorAll<HTMLDetailsElement>(".outline-mobile").forEach((details) => {
  details.addEventListener("click", (event) => {
    if ((event.target as HTMLElement).closest("a")) details.open = false;
  });
});
