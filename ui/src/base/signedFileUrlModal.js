window.app = window.app || {};
window.app.modals = window.app.modals || {};

/**
 * Opens a modal for generating and managing a short-lived, revocable
 * signed download URL for a single record file.
 *
 * @example
 * ```js
 * app.modals.openSignedFileUrl({ record, filename })
 * ```
 *
 * @param {Object} props
 * @param {Object} props.record   - the record that owns the file
 * @param {string} props.filename - the stored file name
 * @param {string} [props.field]  - the file field name (auto-detected if omitted)
 */
window.app.modals.openSignedFileUrl = function(props) {
    const modal = signedFileUrlModal(props || {});
    document.body.appendChild(modal);
    app.modals.open(modal);
};

function signedFileUrlModal(props) {
    const uniqueId = "signedfile_" + app.utils.randomString();

    const data = store({
        isLoading: false,
        isRevoking: false,
        url: "",
        token: "",
        tokenId: "",
        expiresAt: "",
        duration: 600,
        disposition: "",
        error: "",
        get collection() {
            return app.store.collections.find(
                (c) => c.id == props.record?.collectionId || c.name == props.record?.collectionName,
            );
        },
        get field() {
            if (props.field) {
                return props.field;
            }
            // auto-detect the file field that contains the file
            return data.collection?.fields?.find(
                (f) => f.type == "file" && app.utils.toArray(props.record?.[f.name]).includes(props.filename),
            )?.name;
        },
    });

    async function generate() {
        if (data.isLoading || !data.field) {
            return;
        }

        data.isLoading = true;
        data.error = "";

        try {
            const res = await app.pb.send("/api/files/signed-token", {
                method: "POST",
                body: {
                    collection: data.collection.name,
                    recordId: props.record.id,
                    fileField: data.field,
                    filename: props.filename,
                    duration: parseInt(data.duration, 10) || 600,
                    disposition: data.disposition || "",
                },
            });

            data.url = res.url;
            data.token = res.token;
            data.expiresAt = res.expiresAt;

            // extract the jti for the revoke action
            try {
                const payload = JSON.parse(atob(res.token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
                data.tokenId = payload.jti || "";
            } catch (_) {
                data.tokenId = "";
            }
        } catch (err) {
            data.error = err?.response?.message || err?.message || "Failed to generate signed URL.";
            app.checkApiError(err);
        }

        data.isLoading = false;
    }

    async function revoke() {
        if (!data.tokenId || data.isRevoking) {
            return;
        }

        const confirmed = await new Promise((resolve) => {
            app.modals.confirm(
                "Revoke this signed URL? Anyone currently holding it will immediately lose access.",
                () => resolve(true),
                () => resolve(false),
            );
        });
        if (!confirmed) {
            return;
        }

        data.isRevoking = true;

        try {
            await app.pb.send("/api/files/signed-token/" + encodeURIComponent(data.tokenId), {
                method: "DELETE",
            });
            app.toasts.success("Signed URL revoked.");
            reset();
        } catch (err) {
            app.checkApiError(err);
        }

        data.isRevoking = false;
    }

    function reset() {
        data.url = "";
        data.token = "";
        data.tokenId = "";
        data.expiresAt = "";
    }

    return t.div(
        {
            className: "modal popup signed-file-url-modal",
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h6(null, "Signed download URL"),
        ),
        t.div(
            { className: "modal-content" },
            t.p(
                { className: "txt alt-text" },
                "Generates a short-lived link that doesn't require login. It works in emails and external services, is bound to this exact file, and can be revoked at any time.",
            ),
            // target summary
            t.div({ className: "alert block" }, () => [
                t.div({ className: "txt small" }, "File"),
                t.strong({ className: "txt break" }, () => props.filename),
                t.div({ className: "txt small m-t-5" }, () => "Field: " + (data.field || "?")),
            ]),
            // form (shown before generation and after revocation)
            t.form(
                {
                    id: uniqueId + "_form",
                    hidden: () => !!data.url,
                    className: "block",
                    onsubmit: (e) => {
                        e.preventDefault();
                        generate();
                    },
                },
                t.div(
                    { className: "grid" },
                    t.div(
                        { className: "col-sm-6" },
                        t.div(
                            { className: "field" },
                            t.label({ htmlFor: uniqueId + "_duration" }, "Expires after (seconds)"),
                            t.input({
                                id: uniqueId + "_duration",
                                type: "number",
                                min: 10,
                                max: 86400,
                                step: 1,
                                value: () => data.duration,
                                oninput: (e) => (data.duration = parseInt(e.target.value, 10) || 600),
                            }),
                            t.div({ className: "field-help" }, "Between 10s and 86400s (24h). Default 10 minutes."),
                        ),
                    ),
                    t.div(
                        { className: "col-sm-6" },
                        t.div(
                            { className: "field" },
                            t.label({ htmlFor: uniqueId + "_dsp" }, "Response type"),
                            t.select(
                                {
                                    id: uniqueId + "_dsp",
                                    value: () => data.disposition,
                                    onchange: (e) => (data.disposition = e.target.value),
                                },
                                t.option({ value: "" }, "Auto (preview images/pdf, download others)"),
                                t.option({ value: "inline" }, "Inline (preview in browser)"),
                                t.option({ value: "attachment" }, "Attachment (force download)"),
                            ),
                        ),
                    ),
                ),
                () =>
                    data.error
                        ? t.div({ className: "alert error m-t-10" }, () => data.error)
                        : null,
            ),
            // result
            t.div(
                { hidden: () => !data.url, className: "block" },
                t.div(
                    { className: "alert success signed-file-url-result" },
                    t.div({ className: "signed-file-url-text" }, () => data.url),
                    t.div(
                        { className: "m-t-5 txt small" },
                        "Expires: ",
                        t.strong(null, () => data.expiresAt || ""),
                    ),
                ),
                t.div(
                    { className: "flex gap-10 m-t-10" },
                    app.components.copyButton(() => data.url),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm secondary",
                            onclick: () => window.open(data.url, "_blank", "noreferrer,noopener"),
                        },
                        t.i({ className: "ri-external-link-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Open"),
                    ),
                ),
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    onclick: () => app.modals.close(),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            () =>
                data.url
                    ? [
                        t.button(
                            {
                                type: "button",
                                className: () => `btn danger expanded-lg ${data.isRevoking ? "loading" : ""}`,
                                disabled: () => data.isRevoking,
                                onclick: () => revoke(),
                            },
                            t.i({ className: "ri-shield-keyhole-line", ariaHidden: true }),
                            t.span({ className: "txt" }, "Revoke URL"),
                        ),
                        t.button(
                            {
                                type: "button",
                                className: "btn secondary expanded-lg",
                                onclick: () => reset(),
                            },
                            t.span({ className: "txt" }, "Generate new one"),
                        ),
                    ]
                    : t.button(
                        {
                            type: "submit",
                            htmlForm: uniqueId + "_form",
                            className: () => `btn expanded-lg ${data.isLoading ? "loading" : ""}`,
                            disabled: () => data.isLoading || !data.field,
                        },
                        t.i({ className: "ri-link-m", ariaHidden: true }),
                        t.span({ className: "txt" }, "Generate URL"),
                    ),
        ),
    );
}
