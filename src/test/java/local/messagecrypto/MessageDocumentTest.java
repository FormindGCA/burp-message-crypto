package local.messagecrypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class MessageDocumentTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final CryptoProfile PROFILE = CryptoEngineTest.legacy();
    private static final CryptoEngine ENGINE = new CryptoEngine(PROFILE);
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static MessageDocument open(String value, boolean form) {
        return MessageDocument.open(bytes(value), form, StandardCharsets.UTF_8, PROFILE);
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static ObjectNode field(ObjectNode root, String id) {
        for (var node : root.withArray("fields")) if (node.get("id").asText().equals(id)) return (ObjectNode) node;
        throw new AssertionError("Missing field " + id);
    }

    @Test void unchangedFormIsByteExactWithDuplicateNamesAndOddEscaping() {
        String body = "action=routemessage&x=a%20b&x=a+b&empty=&flag&msg=%3crequest%2F%3e&";
        var doc = open(body, true);
        assertArrayEquals(bytes(body), doc.apply(doc.json()));
    }

    @Test void encryptedPasswordEditAndUntouchedParameters() throws Exception {
        String cipher = ENGINE.encryptText("original");
        String body = "action=createetk&password=" + encode(cipher) + "&ctx=a%20b&password=plain";
        var doc = open(body, true);
        var json = (ObjectNode) JSON.readTree(doc.json());
        assertEquals("original", field(json, "form.1").get("value").asText());
        field(json, "form.1").put("value", "changed");
        String actual = new String(doc.apply(json.toString()), StandardCharsets.UTF_8);
        assertEquals("action=createetk&password=" + encode(ENGINE.encryptText("changed")) + "&ctx=a%20b&password=plain", actual);
    }

    @Test void nestedXmlCiphertextEditPreservesXmlWhitespace() throws Exception {
        String xml = "<?xml version='1.0'?><Request>\n  <Change encrypted='true'>" + ENGINE.encryptText("old") + "</Change>\n</Request>";
        var doc = open("action=routemessage&msg=" + encode(xml), true);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.1.cipher.0").put("value", "new & <value>");
        String actual = new String(doc.apply(json.toString()), StandardCharsets.UTF_8);
        assertEquals(xml.replace(ENGINE.encryptText("old"), ENGINE.encryptText("new & <value>")), URLDecoder.decode(actual.substring(actual.indexOf("msg=") + 4), StandardCharsets.UTF_8));
    }

    @Test void responseXmlEditingAndWholeEncryptedBody() throws Exception {
        var doc = open("<Response>" + ENGINE.encryptText("readable") + "</Response>", false);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "body.cipher.0").put("value", "updated");
        assertEquals("<Response>" + ENGINE.encryptText("updated") + "</Response>", new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
        var whole = open(ENGINE.encryptText("payload"), false);
        var wholeJson = (ObjectNode) JSON.readTree(whole.json());
        assertEquals("payload", field(wholeJson, "body").get("value").asText());
    }

    @Test void changingPlainParameterDoesNotReencryptOtherFields() throws Exception {
        String body = "name=old&password=" + encode(ENGINE.encryptText("secret"));
        var doc = open(body, true);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.0").put("value", "new");
        assertEquals(body.replace("name=old", "name=new"), new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
    }

    @Test void malformedJsonAndOverlappingEditsAreRejected() throws Exception {
        var doc = open("msg=" + encode("<Value>" + ENGINE.encryptText("x") + "</Value>"), true);
        assertThrows(IllegalArgumentException.class, () -> doc.apply("not json"));
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.0").put("value", "<different/>");
        field(json, "form.0.cipher.0").put("value", "y");
        assertThrows(IllegalArgumentException.class, () -> doc.apply(json.toString()));
    }

    @Test void noKeyKeepsEncryptedSpansLockedAndOtherFieldsEditable() throws Exception {
        String body = "password=" + encode(ENGINE.encryptText("x")) + "&name=old";
        var doc = MessageDocument.open(bytes(body), true, StandardCharsets.UTF_8, CryptoProfile.defaults());
        var json = (ObjectNode) JSON.readTree(doc.json());
        assertTrue(field(json, "form.0").get("locked").asBoolean());
        field(json, "form.1").put("value", "new");
        assertEquals(body.replace("name=old", "name=new"), new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
    }

    @Test void encryptionCanBeExplicitlyEnabledForPlainField() throws Exception {
        var doc = open("value=plain", true);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.0").put("encrypted", true);
        assertEquals("value=" + encode(ENGINE.encryptText("plain")), new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
    }

    @Test void twoEncryptedSpansAndXmlAttributePlaintextEscaping() throws Exception {
        String xml = "<Request first='" + ENGINE.encryptText("first") + "'><Value>" + ENGINE.encryptText("second") + "</Value></Request>";
        var doc = open(xml, false);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "body.cipher.0").put("value", "a'&<b>").put("encrypted", false);
        field(json, "body.cipher.1").put("value", "a much longer new value");
        String expected = xml.replace(ENGINE.encryptText("first"), "a&apos;&amp;&lt;b&gt;")
                .replace(ENGINE.encryptText("second"), ENGINE.encryptText("a much longer new value"));
        assertEquals(expected, new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
    }

    @Test void fieldDeletionAndDuplicateIdsAreRejected() throws Exception {
        var doc = open("a=one&b=two", true);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.1").put("id", "form.0");
        final var duplicate = json.toString();
        assertThrows(IllegalArgumentException.class, () -> doc.apply(duplicate));
        json = (ObjectNode) JSON.readTree(doc.json());
        json.withArray("fields").remove(0);
        final var deleted = json.toString();
        assertThrows(IllegalArgumentException.class, () -> doc.apply(deleted));
    }

    @Test void zeroKeyLockedFieldCannotBeUnlockedByJson() throws Exception {
        var doc = MessageDocument.open(bytes("password=" + encode(ENGINE.encryptText("x"))), true,
                StandardCharsets.UTF_8, CryptoProfile.defaults());
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.0").put("locked", false).put("value", "edited");
        assertThrows(IllegalArgumentException.class, () -> doc.apply(json.toString()));
    }

    @Test void profileIsCapturedEvenIfOriginalKeyArrayChanges() throws Exception {
        byte[] key = CryptoEngineTest.KEY.clone();
        var settings = CryptoEngineTest.profile("AES", "ECB", CryptoProfile.Padding.ZERO, CryptoProfile.Encoding.HEX, key, new byte[0]);
        var doc = MessageDocument.open(bytes("value=" + encode(ENGINE.encryptText("one"))), true, StandardCharsets.UTF_8, settings);
        java.util.Arrays.fill(key, (byte)0);
        var json = (ObjectNode) JSON.readTree(doc.json());
        field(json, "form.0").put("value", "two");
        assertEquals("value=" + encode(ENGINE.encryptText("two")), new String(doc.apply(json.toString()), StandardCharsets.UTF_8));
    }

    @Test void gcmDecryptsButRefusesAutomaticNonceReuse() throws Exception {
        var settings = CryptoEngineTest.profile("AES", "GCM", CryptoProfile.Padding.NONE, CryptoProfile.Encoding.HEX,
                CryptoEngineTest.KEY, new byte[12]);
        String wire = new CryptoEngine(settings).encryptText("one");
        var doc = MessageDocument.open(bytes(wire), false, StandardCharsets.UTF_8, settings);
        var json = (ObjectNode) JSON.readTree(doc.json());
        assertEquals("one", field(json, "body").get("value").asText());
        field(json, "body").put("value", "two");
        assertThrows(IllegalArgumentException.class, () -> doc.apply(json.toString()));
    }
}
