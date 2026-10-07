package local.messagecrypto;

import java.nio.charset.Charset;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public final class MessageDocument {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_BYTES = 2 * 1024 * 1024;
    private final byte[] original;
    private final boolean form;
    private final Charset charset;
    private final CryptoProfile profile;
    private final LinkedHashMap<String, Field> fields = new LinkedHashMap<>();
    private final List<Part> parts = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();
    private final Map<String, String> originalParentValues = new HashMap<>();

    private record Part(String raw, String namePrefix, String id) { }
    private record Field(String id, String label, String value, boolean encrypted, boolean locked,
                         String parent, int start, int end, boolean xml) { }
    private record Edit(String value, boolean encrypted) { }

    private MessageDocument(byte[] body, boolean form, Charset charset, CryptoProfile profile) {
        if (body.length > MAX_BYTES) throw new IllegalArgumentException("Body exceeds the 2 MiB editor limit.");
        this.original = body.clone(); this.form = form; this.charset = charset; this.profile = profile;
        String text;
        try {
            text = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
        } catch (java.nio.charset.CharacterCodingException error) {
            throw new IllegalArgumentException("Body is not valid text in the selected HTTP charset.");
        }
        if (form) {
            String[] segments = text.split("&", -1);
            for (int index = 0; index < segments.length; index++) {
                String segment = segments[index];
                if (segment.isEmpty()) { parts.add(new Part(segment, "", null)); continue; }
                int equals = segment.indexOf('=');
                String rawName = equals < 0 ? segment : segment.substring(0, equals);
                String rawValue = equals < 0 ? "" : segment.substring(equals + 1);
                String id = "form." + index;
                addParent(id, urlDecode(rawName), urlDecode(rawValue));
                parts.add(new Part(segment, rawName + "=", id));
            }
        } else addParent("body", "Response/body text", text);
    }

    public static MessageDocument open(byte[] body, boolean form, Charset charset, CryptoProfile profile) {
        return new MessageDocument(body, form, charset, profile);
    }

    private String urlDecode(String value) {
        try { return URLDecoder.decode(value, charset); }
        catch (IllegalArgumentException error) { throw new IllegalArgumentException("Malformed form URL encoding."); }
    }

    private void addParent(String id, String label, String value) {
        originalParentValues.put(id, value);
        if (fields.size() >= 2048) throw new IllegalArgumentException("Too many editable fields (maximum 2048).");
        boolean whole = !profile.prefix().isEmpty() && value.startsWith(profile.prefix())
                && !value.contains("<") && !value.contains("\n");
        if (whole) {
            addEncrypted(id, label, value, null, 0, value.length(), false);
            return;
        }
        boolean xml = value.stripLeading().startsWith("<");
        fields.put(id, new Field(id, label, value, false, false, null, 0, value.length(), xml));
        if (profile.prefix().isEmpty()) return;
        String alphabet = profile.encoding() == CryptoProfile.Encoding.BASE64 ? "[A-Za-z0-9+/]+={0,2}" : "[0-9a-fA-F]+";
        var matcher = Pattern.compile(Pattern.quote(profile.prefix()) + alphabet).matcher(value);
        int index = 0;
        while (matcher.find()) {
            if (fields.size() >= 2048) throw new IllegalArgumentException("Too many editable fields (maximum 2048).");
            addEncrypted(id + ".cipher." + index++, label + " encrypted span " + index,
                    matcher.group(), id, matcher.start(), matcher.end(), xml);
        }
    }

    private void addEncrypted(String id, String label, String cipher, String parent, int start, int end, boolean xml) {
        try {
            String plain = new CryptoEngine(profile).decryptText(cipher);
            fields.put(id, new Field(id, label, plain, true, false, parent, start, end, xml));
        } catch (IllegalArgumentException error) {
            fields.put(id, new Field(id, label, cipher, true, true, parent, start, end, xml));
            warnings.add(id + ": " + error.getMessage());
        }
    }

    public String json() {
        ObjectNode root = JSON.createObjectNode();
        root.put("instructions", "Edit value/encrypted only. IDs identify duplicate form parameters and encrypted spans. Locked fields cannot be edited. Do not edit a parent and its spans together.");
        var rows = root.putArray("fields");
        for (var field : fields.values()) {
            var row = rows.addObject();
            row.put("id", field.id()); row.put("label", field.label()); row.put("value", field.value());
            row.put("encrypted", field.encrypted()); row.put("locked", field.locked());
        }
        var notices = root.putArray("warnings");
        warnings.forEach(notices::add);
        try { return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root); }
        catch (java.io.IOException error) { throw new IllegalStateException(error); }
    }

    public byte[] apply(String json) {
        if (json.length() > MAX_BYTES * 8) throw new IllegalArgumentException("Editor document is too large.");
        JsonNode root;
        try { root = JSON.readTree(json); }
        catch (java.io.IOException error) { throw new IllegalArgumentException("Invalid editor JSON."); }
        if (root == null || !root.isObject() || !root.path("fields").isArray() || root.path("fields").size() != fields.size())
            throw new IllegalArgumentException("Keep the original fields array and its IDs.");
        Map<String, Edit> edits = new HashMap<>();
        for (var row : root.path("fields")) {
            if (!row.path("id").isTextual() || !row.path("value").isTextual() || !row.path("encrypted").isBoolean())
                throw new IllegalArgumentException("Each field requires a string id/value and boolean encrypted.");
            String id = row.path("id").asText();
            Field field = fields.get(id);
            if (field == null || edits.containsKey(id)) throw new IllegalArgumentException("Unknown or duplicate field ID.");
            Edit edit = new Edit(row.path("value").asText(), row.path("encrypted").asBoolean());
            if (field.locked() && changed(field, edit)) throw new IllegalArgumentException("Encrypted field " + id + " is locked; configure a valid key and reopen the message.");
            edits.put(id, edit);
        }
        boolean modified = fields.values().stream().anyMatch(field -> changed(field, edits.get(field.id())));
        if (!modified) return original.clone();
        if (form) {
            List<String> segments = new ArrayList<>();
            for (var part : parts) {
                if (part.id() == null) { segments.add(part.raw()); continue; }
                String value = parentValue(part.id(), edits);
                Field field = fields.get(part.id());
                boolean childrenChanged = fields.values().stream().anyMatch(child -> part.id().equals(child.parent()) && changed(child, edits.get(child.id())));
                if (!changed(field, edits.get(field.id())) && !childrenChanged) segments.add(part.raw());
                else segments.add(part.namePrefix() + URLEncoder.encode(value, charset));
            }
            return String.join("&", segments).getBytes(charset);
        }
        return parentValue("body", edits).getBytes(charset);
    }

    private String parentValue(String id, Map<String, Edit> edits) {
        Field parent = fields.get(id);
        Edit edit = edits.get(id);
        var children = fields.values().stream().filter(field -> id.equals(field.parent()) && changed(field, edits.get(field.id())))
                .sorted(Comparator.comparingInt(Field::start).reversed()).toList();
        if (changed(parent, edit)) {
            if (!children.isEmpty()) throw new IllegalArgumentException("Edit either parent " + id + " or its encrypted spans, not both.");
            return wireValue(edit);
        }
        // Whole encrypted parents with unchanged plaintext are emitted from original form bytes.
        if (parent.encrypted()) {
            return originalParentValues.get(id);
        }
        StringBuilder value = new StringBuilder(parent.value());
        for (var child : children) {
            String replacement = wireValue(edits.get(child.id()));
            if (child.xml()) replacement = xmlEscape(replacement);
            value.replace(child.start(), child.end(), replacement);
        }
        return value.toString();
    }

    private String wireValue(Edit edit) {
        if (edit.encrypted() && profile.mode().equals("GCM"))
            throw new IllegalArgumentException("Automatic GCM re-encryption requires nonce-aware framing. Use the scratchpad with a fresh nonce and edit the raw wire value instead.");
        return edit.encrypted() ? new CryptoEngine(profile).encryptText(edit.value()) : edit.value();
    }

    private static boolean changed(Field field, Edit edit) {
        return !field.value().equals(edit.value()) || field.encrypted() != edit.encrypted();
    }

    private static String xmlEscape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
