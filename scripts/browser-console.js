/* RiftHound passive browser helper — use only on authorized targets/accounts. */
(() => {
  const summarize = data => data && typeof data === 'object'
    ? {type: Array.isArray(data) ? 'array' : 'object', keys: Object.keys(data).slice(0,30)}
    : {type: typeof data, preview: String(data).slice(0,120)};
  window.addEventListener('message', e => {
    console.table([{origin:e.origin, opener:e.source===window.opener, sameSource:e.source===window, ...summarize(e.data)}]);
  }, true);
  window.__rifthound = {
    inventory: () => ({origin:location.origin, opener:!!window.opener, localStorageKeys:Object.keys(localStorage), sessionStorageKeys:Object.keys(sessionStorage)}),
    note: 'Use harmless canaries; do not print or export real tokens.'
  };
  console.info('[RiftHound] passive message observer installed. Run __rifthound.inventory()');
})();
