    // Apply the saved theme before CSS is painted. app.js restores it again
    // after load and synchronizes changes across open HAW-KI tabs.
    (() => {
        const normalize = (value) => value === "light" || value === "dark" ? value : null;
        let saved = null;

        try {
            saved = normalize(localStorage.getItem("hawki-theme-v2"));
        } catch {
            // Use the cookie fallback below.
        }

        if (!saved) {
            const prefix = "hawki_theme_v2=";
            const item = document.cookie
                .split(";")
                .map((part) => part.trim())
                .find((part) => part.startsWith(prefix));
            saved = normalize(item ? decodeURIComponent(item.slice(prefix.length)) : null);
        }

        // The bright operations theme is the default; the dark theme stays one
        // click away and is remembered. The key changed with the redesign so
        // everyone starts from the new default once.
        const theme = saved || "light";
        document.documentElement.dataset.theme = theme;
        document.documentElement.style.colorScheme = theme;
    })();
