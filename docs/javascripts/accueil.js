/* Accueil : bandeau défilant, boutons magnétiques et entrée animée (GSAP + ScrollTrigger, chargés par overrides/main.html).
   Sans GSAP ou en mouvement réduit : tout est visible, rien ne bouge. */
(function () {
  const track = document.querySelector(".dt-marquee .track");
  if (track) {                                     /* quatre copies pour une boucle sans couture ; seule la première est lue */
    const words = track.innerHTML;
    track.innerHTML = words + [1, 2, 3].map(() => words.replace(/<span>/g, '<span aria-hidden="true">')).join("");
  }

  if (!window.gsap || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  gsap.registerPlugin(ScrollTrigger);
  gsap.defaults({ ease: "power3.out", duration: .6 });

  /* titre découpé en lettres, la version lisible reste pour les lecteurs d'écran */
  const h1 = document.querySelector(".dt-hero h1");
  if (h1) {
    const txt = h1.textContent.trim();
    h1.innerHTML = `<span class="dt-sr">${txt}</span>` + txt.split(" ")
      .map(w => `<span class="w" aria-hidden="true">${[...w].map(c => `<span class="ch">${c}</span>`).join("")}</span>`).join(" ");
  }

  if (track) gsap.to(track, { xPercent: -50, ease: "none", duration: 40, repeat: -1 });

  if (matchMedia("(pointer: fine)").matches) document.querySelectorAll(".dt-btn").forEach(el => {
    const xT = gsap.quickTo(el, "x", { duration: .35 }), yT = gsap.quickTo(el, "y", { duration: .35 });
    el.addEventListener("pointermove", e => { const r = el.getBoundingClientRect(); xT((e.clientX - r.left - r.width / 2) * .22); yT((e.clientY - r.top - r.height / 2) * .3); });
    el.addEventListener("pointerleave", () => { xT(0); yT(0); });
  });

  /* entrée : invite, titre, propos, puis le flux d'alertes ligne par ligne */
  gsap.timeline({ delay: .05 })
    .from(".dt-prompt, .dt-status", { autoAlpha: 0, y: 8, stagger: .08, duration: .4 })
    .from(".dt-hero h1 .ch", { yPercent: 110, stagger: .018, duration: .75, ease: "expo.out" }, "-=.15")
    .from(".dt-role", { y: 14, autoAlpha: 0 }, "-=.5")
    .from(".dt-lede, .dt-cta > *", { y: 12, autoAlpha: 0, stagger: .05, duration: .45 }, "-=.4")
    .from(".dt-hero-log", { autoAlpha: 0, y: 16, duration: .5 }, "-=.5")
    .from(".dt-log li", { autoAlpha: 0, x: -10, stagger: .1, duration: .35, ease: "power2.out" }, "-=.2");

  /* chiffres clés : comptage une fois à l'écran */
  document.querySelectorAll(".kpis strong").forEach(b => {
    const m = b.innerHTML.match(/^(\d+)(.*)$/s); if (!m) return;
    const o = { v: 0 }, end = +m[1], suf = m[2];
    gsap.to(o, { v: end, duration: 1.1, ease: "power2.out", scrollTrigger: { trigger: b, start: "top 92%", once: true },
      onUpdate: () => { b.innerHTML = Math.round(o.v) + suf; } });
  });

  /* sections : arrivée sobre au défilement */
  ScrollTrigger.batch(".md-content__inner > h2, .grid.cards > ul > li, .md-content__inner > table, .md-content__inner > p > img", {
    start: "top 92%", once: true,
    onEnter: b => gsap.from(b, { y: 18, autoAlpha: 0, stagger: .06, duration: .5, overwrite: true })
  });

  document.fonts && document.fonts.ready.then(() => ScrollTrigger.refresh());
})();
