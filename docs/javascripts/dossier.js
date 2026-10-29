/* Charte « Dossier technique » : effets communs à toutes les pages.
   Fond vivant (grille de points + lumière qui suit le pointeur), halo sous le pointeur, barre de lecture.
   Sans JS ou en mouvement réduit : la doc reste identique, seul le décor est figé. */
(function () {
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const home = document.documentElement.classList.contains("is-home");

  /* ── Barre de lecture ── */
  const bar = document.querySelector(".dt-progress");
  if (bar) {
    const upd = () => {
      const max = document.documentElement.scrollHeight - innerHeight;
      bar.style.setProperty("--dt-p", max > 0 ? Math.min(1, scrollY / max) : 0);
    };
    addEventListener("scroll", upd, { passive: true });
    addEventListener("resize", upd);
    upd();
  }

  /* ── Fond vivant (même dessin que le portfolio, plus discret hors accueil) ── */
  const cv = document.getElementById("dt-field");
  if (cv && cv.getContext) {
    const cx = cv.getContext("2d");
    const G = 26, BASE = home ? .13 : .09, LIGHT = home ? .16 : .1;
    let W = 0, H = 0, dpr = 1, mx = -1e4, my = -1e4, sx = -1e4, sy = -1e4, t = 0, col = {}, running = false;
    const readCol = () => {
      const c = getComputedStyle(document.body);
      col = { dot: c.getPropertyValue("--dt-muted").trim(), acc: c.getPropertyValue("--dt-accent").trim() };
      const k = document.createElement("canvas").getContext("2d");
      k.fillStyle = col.acc; k.fillRect(0, 0, 1, 1);
      col.rgb = [...k.getImageData(0, 0, 1, 1).data].slice(0, 3).join(",");   /* accent en RVB pour le dégradé */
    };
    const size = () => {
      dpr = Math.min(devicePixelRatio || 1, 2); W = innerWidth; H = innerHeight;
      cv.width = W * dpr; cv.height = H * dpr; cx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const draw = () => {
      t += .01; sx += (mx - sx) * .14; sy += (my - sy) * .14;            /* la lumière suit avec un léger retard */
      cx.clearRect(0, 0, W, H);
      if (sx > -1e3) {
        const g = cx.createRadialGradient(sx, sy, 0, sx, sy, 460);
        g.addColorStop(0, `rgba(${col.rgb},${LIGHT})`); g.addColorStop(.55, `rgba(${col.rgb},${LIGHT / 3})`); g.addColorStop(1, `rgba(${col.rgb},0)`);
        cx.globalAlpha = 1; cx.fillStyle = g; cx.fillRect(sx - 460, sy - 460, 920, 920);
      }
      const off = -(scrollY * .25) % G;                                      /* parallaxe douce au défilement */
      for (let y = off + G / 2; y < H; y += G) for (let x = G / 2; x < W; x += G) {
        const dx = x - sx, dy = y - sy, d = Math.hypot(dx, dy), f = Math.max(0, 1 - d / 200);
        const wv = reduce ? 0 : Math.sin(x * .012 + t) * Math.cos(y * .014 + t * .8);
        const px = x + (d ? dx / d : 0) * f * f * 22, py = y + (d ? dy / d : 0) * f * f * 22;
        cx.globalAlpha = BASE + f * .6 + wv * .04; cx.fillStyle = f > .06 ? col.acc : col.dot;
        cx.beginPath(); cx.arc(px, py, 1 + f * 1.5, 0, 6.283); cx.fill();
      }
      if (!reduce && !document.hidden) requestAnimationFrame(draw); else running = false;
    };
    const start = () => { if (reduce) { draw(); return; } if (!running) { running = true; requestAnimationFrame(draw); } };
    readCol(); size(); start();
    addEventListener("resize", () => { size(); if (reduce) draw(); });
    if (fine && !reduce)
      addEventListener("pointermove", e => { mx = e.clientX; my = e.clientY; if (sx < -1e3) { sx = mx; sy = my; } }, { passive: true });
    document.documentElement.addEventListener("pointerleave", () => { mx = my = -1e4; });
    document.addEventListener("visibilitychange", () => { if (!document.hidden) start(); });
    /* le sélecteur clair/sombre de Material change l'attribut data-md-color-scheme du body */
    new MutationObserver(() => { readCol(); if (reduce) draw(); })
      .observe(document.body, { attributes: true, attributeFilter: ["data-md-color-scheme"] });
    if (reduce) addEventListener("scroll", draw, { passive: true });
  }

  /* ── Halo sous le pointeur (cartes, panneaux) ── */
  if (fine) {
    const HALO = ".grid.cards > ul > li, .grid > .card, .dt-panel";
    let last = null;
    document.addEventListener("pointermove", e => {
      const el = e.target.closest && e.target.closest(HALO);
      if (last && last !== el) { last.style.removeProperty("--mx"); last.style.removeProperty("--my"); }
      last = el;
      if (el) {
        const r = el.getBoundingClientRect();
        el.style.setProperty("--mx", (e.clientX - r.left) + "px");
        el.style.setProperty("--my", (e.clientY - r.top) + "px");
      }
    }, { passive: true });
  }
})();
