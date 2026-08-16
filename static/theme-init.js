    // Apply the saved theme before CSS is painted. app.js restores it again
    // after load and synchronizes changes across open HAW-KI tabs.
    (() => {
        const normalize = (value) => value === "light" || value === "dark" ? value : null;
        let saved = null;

        try {
            saved = normalize(localStorage.getItem("hawki-theme"));
        } catch {
            // Use the cookie fallback below.
        }

        if (!saved) {
            const prefix = "hawki_theme=";
            const item = document.cookie
                .split(";")
                .map((part) => part.trim())
                .find((part) => part.startsWith(prefix));
            saved = normalize(item ? decodeURIComponent(item.slice(prefix.length)) : null);
        }

        const preferred = window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
        const theme = saved || preferred;
        document.documentElement.dataset.theme = theme;
        document.documentElement.style.colorScheme = theme;
    })();
