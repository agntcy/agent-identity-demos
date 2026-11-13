// Copyright 2026 AGNTCY Contributors
// SPDX-License-Identifier: Apache-2.0
(() => {
  const dialog = document.createElement('dialog');
  dialog.className = 'diagram-modal';
  dialog.setAttribute('aria-labelledby', 'diagramModalTitle');
  dialog.innerHTML = '<div class="diagram-modal-toolbar"><strong id="diagramModalTitle">AGNTCY diagram</strong><div class="diagram-modal-controls"><button type="button" data-action="out" aria-label="Zoom out">−</button><span data-zoom aria-live="polite">Fit</span><button type="button" data-action="in" aria-label="Zoom in">+</button><button type="button" data-action="fit">Fit to window</button><button type="button" data-action="close" aria-label="Close diagram">Close ✕</button></div></div><div class="diagram-modal-scroll"><div class="diagram-modal-content"></div></div>';
  document.body.append(dialog);
  const content = dialog.querySelector('.diagram-modal-content');
  let active = null, placeholder = null, trigger = null, previousOverflow = '', zoom = 1;
  let consolePanel = null, consolePlaceholder = null;
  function fit() {
    zoom = 1;
    dialog.dataset.fit = 'true';
    content.style.width = '100%';
    dialog.querySelector('[data-zoom]').textContent = 'Fit';
  }
  function changeZoom(delta) {
    zoom = Math.max(.75, Math.min(2.5, zoom + delta));
    dialog.dataset.fit = 'false';
    content.style.width = `${zoom * 100}%`;
    dialog.querySelector('[data-zoom]').textContent = `${Math.round(zoom * 100)}%`;
  }
  document.querySelectorAll('[data-diagram-target]').forEach(button => {
    button.addEventListener('click', () => {
      if (dialog.open) return;
      active = document.querySelector(button.dataset.diagramTarget);
      if (!active) return;
      trigger = button;
      placeholder = document.createComment('diagram original position');
      active.before(placeholder);
      content.append(active);
      dialog.querySelector('#diagramModalTitle').textContent = active.querySelector('h2')?.textContent || 'AGNTCY diagram';
      previousOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      fit();
      if (active.classList.contains("diagram")) changeZoom(0);
      consolePanel = document.querySelector("#liveConsole") || document.querySelector("#sideToast");
      if (consolePanel) { consolePlaceholder = document.createComment("console position"); consolePanel.before(consolePlaceholder); dialog.append(consolePanel); }
      dialog.showModal();
      dialog.querySelector('[data-action="close"]').focus();
    });
  });
  dialog.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => {
    if (button.dataset.action === 'close') dialog.close();
    if (button.dataset.action === 'fit') fit();
    if (button.dataset.action === 'in') changeZoom(.25);
    if (button.dataset.action === 'out') changeZoom(-.25);
  }));
  dialog.addEventListener('click', event => {
    if (event.target === dialog) {
      const bounds = dialog.getBoundingClientRect();
      if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
    }
  });
  dialog.addEventListener('close', () => {
    if (active && placeholder) placeholder.replaceWith(active);
    if (consolePanel && consolePlaceholder) consolePlaceholder.replaceWith(consolePanel);
    consolePanel = consolePlaceholder = null;
    document.body.style.overflow = previousOverflow;
    trigger?.focus();
    active = placeholder = null;
  });
})();
