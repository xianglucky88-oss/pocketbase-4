window.app = window.app || {};
window.app.modals = window.app.modals || {};

/**
 * Opens a modal for generating and revoking revocable signed download URLs
 * for a single record file.
 *
 * @example
 * ```js
 * app.modals.openFileSignedLinks(record, filename)
 * ```
 *
 * @param {Object} record  the target record (must include collectionId/collectionName)
 * @param {string} filename the file from the file field
 */
window.app.modals.openFileSignedLinks = function(record, filename) {
    const modal = fileSignedLinksModal(record, filename);

    document.body.appendChild(modal);

    app.modals.open(modal);
};

const DURATION_PRESETS = [
    { label: "15 minutes", value: 900 },
    { label: "1 hour", value: 3600 },
    { label: "24 hours", value: 86400 },
    { label: "7 days", value: 604800 },
];

function fileSignedLinksModal(record, filename) {
    const data = store({
        isLoading: false,
        isGenerating: false,
        duration: 3600,
        disposition: "auto",
        items: [],
        loadError: "",
    });

    const collectionName = record.collectionName || record.collectionId;

    async function load() {
        data.isLoading = true;
        data.loadError = "";

        try {
            const res = await app.pb.send(
                `/api/files/links?collection=${encodeURIComponent(collectionName)}`
                    + `&record=${encodeURIComponent(record.id)}`
                    + `&file=${encodeURIComponent(filename)}`,
                { method: "GET" },
            );
            data.items = res.items || [];
        } catch (err) {
            console.warn("Failed to load signed file links:", err);
            data.loadError = err?.response?.message || "Failed to load existing signed links.";
        }

        data.isLoading = false;
    }

    async function generate() {
        if (data.isGenerating) {
            return;
        }

        data.isGenerating = true;

        try {
            const res = await app.pb.send("/api/files/links", {
                method: "POST",
                body: {
                    collection: collectionName,
                    record: record.id,
                    file: filename,
                    duration: data.duration,
                    disposition: data.disposition,
                },
            });

            data.items.unshift({
                id: res.id,
                url: res.url,
                file: res.file,
                fileField: res.fileField,
                disposition: res.disposition,
                expiresAt: res.expiresAt,
                created: new Date().toISOString().replace("T", " ").substring(0, 23) + "Z",
                _new: true,
            });
        } catch (err) {
            app.checkApiError(err);
        }

        data.isGenerating = false;
    }

    async function revoke(item) {
        app.modals.confirm(
            `Revoke the signed link for "${filename}"? Anyone holding the URL will lose access immediately.`,
            async () => {
                try {
                    await app.pb.send(`/api/files/links/${encodeURIComponent(item.id)}`, {
                        method: "DELETE",
                    });

                    data.items = data.items.filter((i) => i.id != item.id);
                    app.toasts?.success?.("Signed link revoked.");
                } catch (err) {
                    app.checkApiError(err);
                }
            },
            null,
            { yesButton: "Revoke" },
        );
    }

    return t.div(
        {
            className: "modal popup file-signed-links-modal",
            onbeforeopen: () => load(),
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h6(null, "Signed download links"),
            t.button(
                {
                    type: "button",
                    className: "btn icon transparent close",
                    ariaLabel: "Close",
                    onclick: () => app.modals.close(),
                },
                t.i({ className: "ri-close-line" }),
            ),
        ),
        t.div({ className: "modal-body" }, () => {
            const children = [
                t.p(
                    { className: "txt-hint margin-b-10" },
                    "Short-lived, cookie-free links that can be opened by email clients and external services. "
                        + "Each link is bound to this exact file and can be revoked at any time.",
                ),
                t.div(
                    { className: "file-signed-links-target table-lines margin-b-15" },
                    t.span({ className: "txt-hint" }, "File"),
                    t.strong({ className: "text-ellipsis" }, filename),
                ),
            ];

            if (data.loadError) {
                children.push(t.p({ className: "text-danger margin-b-10" }, data.loadError));
            }

            // generator form
            children.push(
                t.div(
                    { className: "file-signed-links-form table-lines margin-b-15" },
                    t.label({ className: "txt-hint" }, "Expiration"),
                    t.select(
                        {
                            value: () => String(data.duration),
                            onchange: (e) => (data.duration = parseInt(e.target.value)),
                        },
                        DURATION_PRESETS.map((p) =>
                            t.option({ value: p.value, selected: () => data.duration == p.value }, p.label)
                        ),
                    ),
                    t.label({ className: "txt-hint" }, "Response"),
                    t.select(
                        {
                            value: () => data.disposition,
                            onchange: (e) => (data.disposition = e.target.value),
                        },
                        t.option({ value: "auto" }, "Auto (preview or download)"),
                        t.option({ value: "inline" }, "Inline (preview)"),
                        t.option({ value: "attachment" }, "Attachment (download)"),
                    ),
                    t.span(null, ""),
                    t.button(
                        {
                            type: "button",
                            className: "btn primary",
                            disabled: () => data.isGenerating,
                            onclick: () => generate(),
                        },
                        t.i({ className: "ri-link" }),
                        "Generate link",
                    ),
                ),
            );

            if (data.isLoading) {
                children.push(t.span({ className: "loader" }));
                return children;
            }

            if (!data.items.length) {
                children.push(
                    t.p(
                        { className: "txt-hint text-center padding-10" },
                        "There are no active signed links for this file yet.",
                    ),
                );
                return children;
            }

            // existing links list
            children.push(
                t.div(
                    { className: "file-signed-links-list" },
                    () =>
                        data.items.map((item) => {
                            const actions = [
                                t.button(
                                    {
                                        type: "button",
                                        className: "btn icon sm transparent text-danger",
                                        ariaLabel: "Revoke signed URL",
                                        title: "Revoke",
                                        onclick: () => revoke(item),
                                    },
                                    t.i({ className: "ri-shield-cross-line" }),
                                ),
                            ];

                            // the full signed URL (including its secret token) is
                            // available only right after generation - previously
                            // stored rows expose just the jti for revocation
                            if (item.url) {
                                actions.unshift(
                                    t.a(
                                        {
                                            className: "btn icon sm transparent",
                                            href: item.url,
                                            target: "_blank",
                                            rel: "noreferrer,noopener",
                                            title: "Open signed URL",
                                        },
                                        t.i({ className: "ri-external-link-line" }),
                                    ),
                                    app.components.copyButton(
                                        () => item.url,
                                        t.i({ className: "ri-file-copy-line" }),
                                    ),
                                );
                            }

                            return t.div(
                                { className: "file-signed-link-item table-lines", key: item.id },
                                t.div(
                                    { className: "file-signed-link-meta" },
                                    t.span(
                                        { className: "badge sm" },
                                        item.disposition == "attachment"
                                            ? "attachment"
                                            : item.disposition == "inline"
                                              ? "inline"
                                              : "auto",
                                    ),
                                    item.url
                                        ? t.span({ className: "txt-hint" }, "copy it now - the full link is shown only here")
                                        : app.components.formattedDate({
                                              value: item.expiresAt || "",
                                              short: true,
                                          }),
                                ),
                                t.div({ className: "file-signed-link-url" }, actions),
                            );
                        }),
                ),
            );

            return children;
        }),
    );
}
