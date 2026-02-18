/**
 * tm.js — Copy-link-to-heading functionality (vanilla JS)
 */

function copyClipboard(el) {
  var href = window.location.href.split('#')[0];
  var parent = el.parentElement;
  var aref = parent ? parent.getAttribute('id') : '';
  if (!aref) return;

  var url = href + '#' + aref;
  navigator.clipboard.writeText(url).then(function () {
    el.dataset.tooltip = 'Copied!';
    setTimeout(function () {
      el.dataset.tooltip = 'Copy link to heading';
    }, 3000);
  });
}

document.addEventListener('DOMContentLoaded', function () {
  var headings = document.querySelectorAll(
    '.theme-doc-markdown h1, .theme-doc-markdown h2, .theme-doc-markdown h3, .theme-doc-markdown h4, .theme-doc-markdown h5'
  );

  headings.forEach(function (heading) {
    if (!heading.id) {
      return;
    }
    var span = document.createElement('span');
    span.className = 'linky tooltip';
    span.setAttribute('data-tooltip', 'Copy link to heading');
    span.setAttribute('aria-hidden', 'true');
    span.addEventListener('click', function () {
      copyClipboard(span);
    });

    heading.appendChild(span);
    heading.classList.add('anchorLink');
  });
});
