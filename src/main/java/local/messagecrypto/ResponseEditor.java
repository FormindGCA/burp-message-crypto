package local.messagecrypto;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import java.awt.Component;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

final class ResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final EditorSupport support;
    ResponseEditor(MontoyaApi api, EditorCreationContext context, AtomicReference<CryptoProfile> profiles) {
        support = new EditorSupport(api, context, profiles);
    }
    @Override public HttpResponse getResponse() {
        if (support.message == null) return null;
        byte[] body = support.body();
        return Arrays.equals(body, support.original) ? support.message.response()
                : support.message.response().withBody(ByteArray.byteArray(body));
    }
    @Override public void setRequestResponse(HttpRequestResponse message) { support.set(message, true); }
    @Override public boolean isEnabledFor(HttpRequestResponse message) { return support.enabled(message, true); }
    @Override public String caption() { return "Message Crypto"; }
    @Override public Component uiComponent() { return support.panel; }
    @Override public Selection selectedData() { return support.selection(); }
    @Override public boolean isModified() { return support.modified(); }
}
