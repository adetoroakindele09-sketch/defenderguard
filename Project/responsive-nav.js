(() => {
    const toggle = document.getElementById("menuToggle");
    const overlay = document.getElementById("sidebarOverlay");
    const sidebar = document.getElementById("sidebar");
    if (!toggle || !overlay || !sidebar) return;
    const close = () => {
        document.body.classList.remove("menu-open");
        toggle.setAttribute("aria-expanded", "false");
        overlay.hidden = true;
    };
    const open = () => {
        document.body.classList.add("menu-open");
        toggle.setAttribute("aria-expanded", "true");
        overlay.hidden = false;
    };
    toggle.addEventListener("click", () => document.body.classList.contains("menu-open") ? close() : open());
    overlay.addEventListener("click", close);
    sidebar.querySelectorAll("a").forEach(link => link.addEventListener("click", close));
    document.addEventListener("keydown", e => { if (e.key === "Escape") close(); });
    window.addEventListener("resize", () => { if (window.innerWidth > 1000) close(); });
})();
