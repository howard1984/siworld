(() => {
  const dialog = document.querySelector('#wallet-startup');
  const create = document.querySelector('#create');
  const state = document.querySelector('#status');
  const message = document.querySelector('#wallet-startup-message');
  const progress = document.querySelector('#wallet-startup-progress');
  const reload = document.querySelector('#wallet-startup-reload');
  let complete = false;
  let timer;
  const failed = text => {
    if (complete) return;
    clearTimeout(timer);
    message.textContent = text;
    message.classList.add('error');
    dialog.setAttribute('aria-busy', 'false');
    progress.hidden = true;
    reload.hidden = false;
    if (document.activeElement === dialog) reload.focus();
  };
  const moduleError = event => {
    if (event.target instanceof HTMLScriptElement && event.target.type === 'module')
      failed('The local wallet core could not load. Reload the wallet to try again.');
  };
  const update = () => {
    if (complete) return;
    // The application enables creation only after both worker and encrypted storage are ready.
    if (!create.disabled) {
      complete = true;
      clearTimeout(timer);
      observer.disconnect();
      document.removeEventListener('error', moduleError, true);
      dialog.close();
      return;
    }
    if (state.classList.contains('error')) failed(state.textContent);
  };
  const observer = new MutationObserver(update);
  observer.observe(create, {attributes: true, attributeFilter: ['disabled']});
  observer.observe(state, {attributes: true, attributeFilter: ['class'], childList: true, characterData: true, subtree: true});
  document.addEventListener('error', moduleError, true);
  dialog.addEventListener('cancel', event => event.preventDefault());
  reload.addEventListener('click', () => location.reload());
  // Static markup stays visible even before this independent script loads.
  dialog.close();
  dialog.showModal();
  timer = setTimeout(() => failed('The local wallet core has not finished loading. Reload the wallet to try again. Existing encrypted data is preserved.'), 600000);
  update();
})();
