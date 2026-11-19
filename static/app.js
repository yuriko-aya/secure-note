const MAX_PLAINTEXT_BYTES = 64 * 1024 - 16;

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return base64ToBytes(padded + pad);
}

function noteIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] !== "n" || !parts[1]) {
    return "";
  }
  return decodeURIComponent(parts[1]);
}

function showError(element, message) {
  element.hidden = false;
  element.textContent = message;
}

async function encryptMessage(plaintext) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  return { keyBytes, nonce, ciphertext };
}

async function decryptMessage(keyBytes, nonce, ciphertext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
  return new TextDecoder().decode(plain);
}

function initCreate() {
  const form = document.querySelector("#create-form");
  const message = document.querySelector("#message");
  const ttl = document.querySelector("#ttl");
  const views = document.querySelector("#views");
  const button = document.querySelector("#create-button");
  const error = document.querySelector("#create-error");
  const result = document.querySelector("#result");
  const link = document.querySelector("#secret-link");
  const copy = document.querySelector("#copy-button");
  const policy = document.querySelector("#created-policy");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    result.hidden = true;
    const plaintext = message.value;
    if (!plaintext.trim()) {
      showError(error, "Write a message first.");
      return;
    }
    if (new TextEncoder().encode(plaintext).length > MAX_PLAINTEXT_BYTES) {
      showError(error, "Message is too long.");
      return;
    }
    const turnstileToken = document.querySelector("[name='cf-turnstile-response']")?.value?.trim() || "";
    if (!turnstileToken) {
      showError(error, "Complete the Turnstile check.");
      return;
    }
    button.disabled = true;
    try {
      const encrypted = await encryptMessage(plaintext);
      const response = await fetch("/api/notes", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ciphertext: bytesToBase64(encrypted.ciphertext),
          nonce: bytesToBase64(encrypted.nonce),
          ttl_seconds: Number(ttl.value),
          max_views: Number(views.value),
          turnstile_token: turnstileToken,
        }),
      });
      const payload = await response.json();
      if (window.turnstile) {
        window.turnstile.reset();
      }
      if (!response.ok) {
        showError(error, payload.error || "The note could not be saved.");
        return;
      }
      const secret = `${location.origin}/n/${payload.id}#${bytesToBase64Url(encrypted.keyBytes)}`;
      link.value = secret;
      const when = new Date(payload.expires_at * 1000).toLocaleString();
      const viewLabel = views.value === "1" ? "1 view" : `${views.value} views`;
      policy.textContent = `Expires ${when}. ${viewLabel}.`;
      result.hidden = false;
      message.value = "";
    } catch {
      showError(error, "The note could not be saved.");
    } finally {
      button.disabled = false;
    }
  });

  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(link.value);
      copy.textContent = "Copied";
    } catch {
      link.select();
      copy.textContent = "Select the link";
    }
    setTimeout(() => {
      copy.textContent = "Copy";
    }, 1600);
  });
}

function initReveal() {
  const button = document.querySelector("#reveal-button");
  const error = document.querySelector("#note-error");
  const sealed = document.querySelector("#sealed");
  const opened = document.querySelector("#opened");
  const policy = document.querySelector("#policy");
  const plaintext = document.querySelector("#plaintext");
  const id = noteIdFromPath();

  button.addEventListener("click", async () => {
    error.hidden = true;
    const fragment = location.hash.startsWith("#") ? location.hash.slice(1) : "";
    let keyBytes;
    try {
      keyBytes = base64UrlToBytes(decodeURIComponent(fragment));
    } catch {
      keyBytes = new Uint8Array();
    }
    if (!id || keyBytes.length !== 32) {
      showError(error, "This note can't be opened.");
      return;
    }
    button.disabled = true;
    try {
      const response = await fetch(`/api/notes/${encodeURIComponent(id)}/reveal`, { method: "POST" });
      if (response.status === 410) {
        showError(error, "This note is gone.");
        return;
      }
      if (!response.ok) {
        showError(error, "The note could not be retrieved.");
        return;
      }
      const payload = await response.json();
      let text;
      try {
        text = await decryptMessage(
          keyBytes,
          base64ToBytes(payload.nonce),
          base64ToBytes(payload.ciphertext),
        );
      } catch {
        showError(error, "This note can't be opened.");
        return;
      }
      const when = new Date(payload.expires_at * 1000).toLocaleString();
      const remaining = Number(payload.views_remaining);
      const viewText = remaining === 0
        ? `This was the last view. The note has been deleted. It was set to expire ${when}.`
        : `${remaining} ${remaining === 1 ? "view" : "views"} left. Expires ${when}.`;
      policy.textContent = viewText;
      plaintext.textContent = text;
      sealed.hidden = true;
      opened.hidden = false;
    } catch {
      showError(error, "The note could not be retrieved.");
    } finally {
      button.disabled = false;
    }
  });
}

if (location.pathname === "/") {
  initCreate();
} else if (location.pathname.startsWith("/n/")) {
  initReveal();
}
