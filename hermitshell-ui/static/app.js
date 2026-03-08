// Dialog open/close via data attributes
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-dialog-open]');
    if (btn) {
        var dialog = btn.nextElementSibling;
        if (dialog && dialog.tagName === 'DIALOG') dialog.showModal();
        return;
    }
    var cancel = e.target.closest('[data-dialog-close]');
    if (cancel) {
        var dlg = cancel.closest('dialog');
        if (dlg) dlg.close();
        return;
    }
});

// Disable submit buttons on form submission
document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form.tagName !== 'FORM') return;
    var btns = form.querySelectorAll('button[type=submit]');
    btns.forEach(function(btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'wait';
    });
});

// Toggle visibility of a target element via data-toggle-visibility="<selector>"
document.addEventListener('change', function(e) {
    var el = e.target;
    if (el.dataset.toggleVisibility) {
        var target = document.querySelector(el.dataset.toggleVisibility);
        if (target) target.style.display = el.checked ? 'flex' : 'none';
    }
    if (el.dataset.toggleDisabled) {
        var container = el.closest(el.dataset.toggleDisabled);
        if (container) {
            var input = container.querySelector('input[type=password]');
            if (input) input.disabled = !el.checked;
        }
    }
});
