document.addEventListener('DOMContentLoaded', function () {
  var root = document.documentElement;
  var themeToggle = document.getElementById('tm-theme-toggle');
  var sidebar = document.getElementById('tm-sidebar');
  var sidebarToggle = document.getElementById('tm-sidebar-toggle');
  var searchInput = document.getElementById('tm-sidebar-search');
  var navList = document.getElementById('tm-nav-list');
  var pageHeadingsSection = document.querySelector('.tm-page-headings');
  var pageHeadingsList = document.getElementById('tm-page-headings-list');

  function slugify(value) {
    return (value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      var current = root.getAttribute('data-theme') || 'light';
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try {
        localStorage.setItem('tm-theme', next);
      } catch (_) {}
    });
  }

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', function () {
      sidebar.classList.toggle('open');
    });
  }

  if (searchInput && navList) {
    var links = Array.prototype.slice.call(navList.querySelectorAll('a'));
    searchInput.addEventListener('input', function () {
      var query = searchInput.value.trim().toLowerCase();
      links.forEach(function (link) {
        var item = link.parentElement;
        if (!item) return;
        var text = (link.textContent || '').toLowerCase();
        item.style.display = text.includes(query) ? '' : 'none';
      });
    });
  }

  if (pageHeadingsSection && pageHeadingsList) {
    var headings = Array.prototype.slice.call(
      document.querySelectorAll('.tm-content h1, .tm-content h2, .tm-content h3')
    );

    pageHeadingsList.innerHTML = '';

    headings.forEach(function (heading) {
      var tagName = (heading.tagName || '').toUpperCase();
      var level = tagName === 'H1' ? 1 : tagName === 'H2' ? 2 : 3;
      var text = (heading.textContent || '').trim();
      if (!text) return;

      if (!heading.id) {
        var baseId = slugify(text) || 'section';
        var uniqueId = baseId;
        var index = 2;
        while (document.getElementById(uniqueId)) {
          uniqueId = baseId + '-' + index;
          index += 1;
        }
        heading.id = uniqueId;
      }

      var li = document.createElement('li');
      li.className = 'level-' + level;

      var a = document.createElement('a');
      a.href = '#' + heading.id;
      a.textContent = text;

      li.appendChild(a);
      pageHeadingsList.appendChild(li);
    });

    if (pageHeadingsList.children.length === 0) {
      pageHeadingsSection.classList.add('hidden');
    } else {
      pageHeadingsSection.classList.remove('hidden');
    }
  }
});