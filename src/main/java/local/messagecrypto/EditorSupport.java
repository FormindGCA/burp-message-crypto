package local.messagecrypto;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

final class EditorSupport {
    final RawEditor editor;
    final JPanel panel = new JPanel(new BorderLayout());
    final JLabel status = new JLabel();
    final AtomicReference<CryptoProfile> profiles;
    final boolean readOnly;
    HttpRequestResponse message;
    MessageDocument document;
    byte[] original;

    EditorSupport(MontoyaApi api, EditorCreationContext context, AtomicReference<CryptoProfile> profiles) {
        this.profiles = profiles;
        readOnly = context.editorMode() == EditorMode.READ_ONLY;
        editor = api.userInterface().createRawEditor(readOnly ? new EditorOptions[] {EditorOptions.READ_ONLY} : new EditorOptions[0]);
        panel.add(editor.uiComponent(), BorderLayout.CENTER);
        panel.add(status, BorderLayout.NORTH);
        api.userInterface().applyThemeToComponent(panel);
    }

    boolean enabled(HttpRequestResponse candidate, boolean response) {
        if (candidate == null || candidate.request() == null || (response && candidate.response() == null)) return false;
        if (!Pattern.compile(profiles.get().pathPattern()).matcher(candidate.request().path()).find()) return false;
        var headers = response ? candidate.response().headers() : candidate.request().headers();
        String encoding = header(headers, "Content-Encoding");
        return encoding.isBlank() || encoding.equalsIgnoreCase("identity");
    }

    void set(HttpRequestResponse message, boolean response) {
        this.message = message;
        document = null;
        original = response ? message.response().body().getBytes() : message.request().body().getBytes();
        var headers = response ? message.response().headers() : message.request().headers();
        try {
            String contentType = header(headers, "Content-Type");
            Charset charset = StandardCharsets.UTF_8;
            var matcher = Pattern.compile("(?i)charset\\s*=\\s*\"?([^;\\s\"]+)").matcher(contentType);
            if (matcher.find()) charset = Charset.forName(matcher.group(1));
            boolean form = !response && contentType.toLowerCase(java.util.Locale.ROOT).startsWith("application/x-www-form-urlencoded");
            document = MessageDocument.open(original, form, charset, profiles.get());
            editor.setContents(ByteArray.byteArray(document.json().getBytes(StandardCharsets.UTF_8)));
            editor.setEditable(!readOnly);
            status("Edit value/encrypted only. Configuration captured at message open; locked fields retain their ciphertext.", false);
        } catch (IllegalArgumentException error) {
            editor.setContents(ByteArray.byteArray("Message cannot be opened in this editor. Original HTTP message is preserved."));
            editor.setEditable(false);
            status(error.getMessage(), true);
        }
    }

    byte[] body() {
        if (readOnly || document == null || !editor.isModified()) return original;
        try {
            byte[] result = document.apply(new String(editor.getContents().getBytes(), StandardCharsets.UTF_8));
            status("Edits serialized using the captured profile.", false);
            return result;
        } catch (IllegalArgumentException error) {
            status("EDITS NOT APPLIED: " + error.getMessage() + " Original message returned.", true);
            return original;
        }
    }

    boolean modified() { return !readOnly && document != null && editor.isModified(); }
    Selection selection() { return editor.selection().orElse(null); }

    private void status(String text, boolean failed) {
        Runnable update = () -> { status.setText(text); status.setForeground(failed ? new Color(180, 30, 30) : UIManager.getColor("Label.foreground")); };
        if (SwingUtilities.isEventDispatchThread()) update.run(); else SwingUtilities.invokeLater(update);
    }

    private static String header(List<HttpHeader> headers, String name) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst().orElse("");
    }
}
