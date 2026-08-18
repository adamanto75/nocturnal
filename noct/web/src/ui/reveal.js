// Reveal-on-scroll.
//
// Progressive enhancement, and the failure mode is the thing to get right: the
// `.reveal` CSS rule starts content invisible, so if this script never runs the
// page would be blank. Anything that stops us animating — reduced-motion, no
// IntersectionObserver — therefore reveals everything immediately rather than
// leaving it hidden. A page that shows nothing because a script failed is worse
// than a page with no animation at all.
(function () {
  var els = [].slice.call(document.querySelectorAll('.reveal'));
  if (!els.length) return;

  var reduce = window.matchMedia &&
               window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Bail before opting in to the hidden state. Nothing has been hidden yet, so
  // returning here simply leaves the page as it already is: readable.
  if (reduce || !('IntersectionObserver' in window)) return;

  // Only now do we let the CSS hide things, having established we can reveal
  // them again.
  document.documentElement.classList.add('js-reveal');

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (en.isIntersecting) {
        en.target.classList.add('in');
        io.unobserve(en.target);   // once revealed, stop watching
      }
    });
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.06 });

  els.forEach(function (e) { io.observe(e); });
})();
