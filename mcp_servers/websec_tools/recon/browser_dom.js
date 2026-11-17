() => {
    const cssEscape = (value) => {
        if (window.CSS && typeof window.CSS.escape === "function") {
            return window.CSS.escape(value);
        }
        return String(value).replace(/([^A-Za-z0-9_-])/g, "\\$1");
    };
    const isVisible = (el) => {
        if (!el || el.disabled) return false;
        const style = window.getComputedStyle ? window.getComputedStyle(el) : null;
        if (style && (style.display === "none" || style.visibility === "hidden")) return false;
        return !el.hasAttribute("hidden");
    };
    const uniqueSelector = (el) => {
        if (el.id) {
            const byId = "#" + cssEscape(el.id);
            if (document.querySelectorAll(byId).length === 1) return byId;
        }
        const parts = [];
        let cur = el;
        while (
            cur && cur.nodeType === 1 && cur !== document.body && cur !== document.documentElement
        ) {
            let part = cur.tagName.toLowerCase();
            if (cur.parentElement) {
                const sameTag = Array.from(cur.parentElement.children).filter(
                    (c) => c.tagName === cur.tagName
                );
                if (sameTag.length > 1) {
                    part += `:nth-of-type(${sameTag.indexOf(cur) + 1})`;
                }
            }
            parts.unshift(part);
            cur = cur.parentElement;
        }
        return parts.length ? "body > " + parts.join(" > ") : el.tagName.toLowerCase();
    };
    const normalizeLabelText = (raw) => {
        const cleaned = String(raw || "").trim().replace(/:+$/, "").trim().toLowerCase();
        if (/^[a-z][a-z0-9_-]{0,63}$/.test(cleaned)) return cleaned;
        return "";
    };
    const resolveLabel = (el) => {
        if (el.id) {
            const label = document.querySelector(`label[for="${cssEscape(el.id)}"]`);
            if (label) {
                const candidate = normalizeLabelText(label.innerText || label.textContent || "");
                if (candidate) return candidate;
            }
        }
        const aria = normalizeLabelText(el.getAttribute("aria-label") || "");
        return aria || "";
    };

    const currentUrl = window.location.href;
    const forms = Array.from(document.querySelectorAll("form")).slice(0, 200).map((form) => {
        const rawAction = form.getAttribute("action");
        let resolvedAction = currentUrl;
        try {
            resolvedAction = new URL(rawAction || "", currentUrl).href;
        } catch (e) {
            resolvedAction = rawAction || currentUrl;
        }
        return {
            page_url: currentUrl,
            action: resolvedAction,
            method: (form.getAttribute("method") || form.method || "GET").toUpperCase(),
            enctype: form.getAttribute("enctype") || form.enctype || null,
            id: form.id || null,
            has_password: !!form.querySelector('input[type="password"]'),
            controls: Array.from(form.elements || []).slice(0, 100).map((ctrl) => ({
                name: ctrl.name || null,
                type: (ctrl.type || ctrl.tagName || "").toLowerCase() || null,
                required: !!ctrl.required,
                disabled: !!ctrl.disabled
            }))
        };
    });

    const skipTypes = new Set(["hidden", "submit", "button", "reset", "image"]);
    const domInputs = [];
    for (const el of document.querySelectorAll("input, select, textarea")) {
        if (domInputs.length >= 200) break;
        if (el.closest("form")) continue;
        const inputType = (el.getAttribute("type") || el.type || el.tagName || "").toLowerCase();
        if (skipTypes.has(inputType)) continue;
        const rawName = (el.getAttribute("name") || "").trim();
        const rawId = (el.getAttribute("id") || "").trim();
        const identifier = rawName || rawId || resolveLabel(el);
        if (!identifier) continue;
        domInputs.push({
            page_url: currentUrl,
            name: identifier,
            input_type: inputType || null,
            required: !!el.required,
            disabled: !!el.disabled
        });
    }

    const links = Array.from(document.querySelectorAll("a[href]")).slice(0, 200).map((a) => ({
        url: a.href || a.getAttribute("href") || "",
        raw_href: a.getAttribute("href") || "",
        text: (a.innerText || a.textContent || "").trim(),
        aria_label: a.getAttribute("aria-label") || ""
    }));

    const interactiveSelector =
        'button, input[type="button"], input[type="submit"], input[type="reset"], ' +
        'summary, [role="tab"], [role="button"], [role="menuitem"], [aria-expanded]';
    const interactive = [];
    for (const el of document.querySelectorAll(interactiveSelector)) {
        if (interactive.length >= 200) break;
        if (!isVisible(el)) continue;
        const form = el.closest("form");
        const formMethod = form
            ? (form.getAttribute("method") || form.method || "GET").toUpperCase()
            : null;
        const container = form || el.closest("section, article, nav, main, div") || document.body;
        let hasEmptyRequiredInput = false;
        if (container) {
            for (const inp of container.querySelectorAll("input, select, textarea")) {
                const t = (inp.getAttribute("type") || inp.type || "").toLowerCase();
                if (inp.disabled || skipTypes.has(t)) continue;
                const val = String(inp.value ?? "").trim();
                if (inp.required && !val) {
                    hasEmptyRequiredInput = true;
                    break;
                }
            }
        }
        interactive.push({
            selector: uniqueSelector(el),
            tag: el.tagName.toLowerCase(),
            type: (el.getAttribute("type") || el.type || "").toLowerCase(),
            role: (el.getAttribute("role") || "").toLowerCase(),
            id: el.id || "",
            name: el.getAttribute("name") || "",
            class_name: typeof el.className === "string" ? el.className : "",
            text: (el.innerText || el.textContent || el.value || "").trim(),
            aria_label: el.getAttribute("aria-label") || "",
            aria_expanded: el.getAttribute("aria-expanded") || "",
            aria_controls: el.getAttribute("aria-controls") || "",
            aria_haspopup: (el.getAttribute("aria-haspopup") || "").toLowerCase(),
            href: el.getAttribute("href") || "",
            form_action: el.getAttribute("formaction") || "",
            in_non_get_form: !!(form && formMethod && formMethod !== "GET"),
            form_method: formMethod,
            container_has_empty_required_input: hasEmptyRequiredInput
        });
    }

    const captchaEl = document.querySelector(
        '.g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey], ' +
        'iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[src*="turnstile"]'
    );
    const hasPasswordInput = !!document.querySelector('input[type="password"]');

    return {
        page_url: currentUrl,
        forms,
        dom_inputs: domInputs,
        links,
        interactive,
        has_captcha: !!captchaEl,
        captcha_selector: captchaEl ? uniqueSelector(captchaEl) : null,
        has_password_input: hasPasswordInput
    };
}

