

function copyClipboard(el) {

    // get base URL
    var href=window.location.href.split('#')[0];
    
    // anchor link is the heading ID
    var aref=$(el).parent().attr('id');
    var url= href+'#'+aref;

    // copy!
    navigator.clipboard.writeText(url);
    el.dataset.tooltip = 'Copied!';

    setTimeout(() => {
        el.dataset.tooltip = 'Copy link to heading';
    }, 3000);
}

// add clickable copy-links to every heading
$('h1,h2,h3,h4,h5').append('<span class="linky tooltip" data-tooltip="Copy link to heading" aria-hidden="true" onClick="copyClipboard(this)"></span>').addClass('anchorLink');
