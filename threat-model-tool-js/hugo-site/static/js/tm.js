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
    '.tm-content h1, .tm-content h2, .tm-content h3, .tm-content h4, .tm-content h5'
  );

  headings.forEach(function (h) {
    if (!h.id) return;
    var span = document.createElement('span');
    span.className = 'linky tooltip';
    span.setAttribute('data-tooltip', 'Copy link to heading');
    span.setAttribute('aria-hidden', 'true');
    span.addEventListener('click', function () {
      copyClipboard(span);
    });
    h.appendChild(span);
    h.classList.add('anchorLink');
  });
});