(function () {
  if (window.__ebpfPwaInstallBridgeReady) return;
  window.__ebpfPwaInstallBridgeReady = true;
  window.__ebpfPwaInstallPrompt = window.__ebpfPwaInstallPrompt || null;
  window.__ebpfPwaInstalled = window.__ebpfPwaInstalled || false;

  window.addEventListener("beforeinstallprompt", function (event) {
    event.preventDefault();
    window.__ebpfPwaInstallPrompt = event;
    window.dispatchEvent(new Event("ebpf:pwa-install-ready"));
  });

  window.addEventListener("appinstalled", function () {
    window.__ebpfPwaInstallPrompt = null;
    window.__ebpfPwaInstalled = true;
    window.dispatchEvent(new Event("ebpf:pwa-installed"));
  });
})();
