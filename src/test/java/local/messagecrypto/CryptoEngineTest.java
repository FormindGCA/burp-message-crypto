package local.messagecrypto;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class CryptoEngineTest {
    static final byte[] KEY = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
    static CryptoProfile profile(String algorithm, String mode, CryptoProfile.Padding padding,
                                 CryptoProfile.Encoding encoding, byte[] key, byte[] iv) {
        return new CryptoProfile(algorithm, mode, padding, encoding, StandardCharsets.UTF_8,
                "ENC:", key, iv, new byte[0], CryptoProfile.defaults().pathPattern());
    }
    static CryptoProfile legacy() {
        return profile("AES", "ECB", CryptoProfile.Padding.ZERO, CryptoProfile.Encoding.HEX, KEY, new byte[0]);
    }

    @Test void nistAesKnownAnswer() {
        var engine = new CryptoEngine(profile("AES", "ECB", CryptoProfile.Padding.NONE, CryptoProfile.Encoding.HEX, KEY, new byte[0]));
        byte[] plain = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
        byte[] expected = HexFormat.of().parseHex("69c4e0d86a7b0430d8cdb78070b4c55a");
        assertArrayEquals(expected, engine.encrypt(plain));
        assertArrayEquals(plain, engine.decrypt(expected));
    }

    @Test void zeroPaddingAndUnicode() {
        var engine = new CryptoEngine(legacy());
        String text = "value \u00e9 \ud83d\ude80";
        assertEquals(text, engine.decryptText(engine.encryptText(text)));
        assertEquals(16, engine.encrypt("1234567890123456".getBytes(StandardCharsets.UTF_8)).length);
        assertEquals(16, engine.encrypt("short".getBytes(StandardCharsets.UTF_8)).length);
        assertEquals(engine.encryptText(text), engine.encryptText(text));
    }

    @Test void cbcPkcs7Base64() {
        var engine = new CryptoEngine(profile("AES", "CBC", CryptoProfile.Padding.PKCS7,
                CryptoProfile.Encoding.BASE64, KEY, new byte[16]));
        assertEquals("a\u0000b", engine.decryptText(engine.encryptText("a\u0000b")));
        assertEquals(32, engine.encrypt("1234567890123456".getBytes(StandardCharsets.UTF_8)).length);
    }

    @Test void gcmAuthenticatesCiphertext() {
        var engine = new CryptoEngine(profile("AES", "GCM", CryptoProfile.Padding.NONE,
                CryptoProfile.Encoding.HEX, KEY, new byte[12]));
        byte[] encrypted = engine.encrypt("message".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("message".getBytes(StandardCharsets.UTF_8), engine.decrypt(encrypted));
        encrypted[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> engine.decrypt(encrypted));
    }

    @Test void tripleDesRoundTrip() {
        var engine = new CryptoEngine(profile("DESede", "CBC", CryptoProfile.Padding.PKCS7,
                CryptoProfile.Encoding.BASE64, new byte[24], new byte[8]));
        assertEquals("synthetic", engine.decryptText(engine.encryptText("synthetic")));
    }

    @Test void invalidSettingsAndCiphertextFailExplicitly() {
        assertThrows(IllegalArgumentException.class, () -> new CryptoEngine(CryptoProfile.defaults()).encryptText("x"));
        assertThrows(IllegalArgumentException.class, () -> new CryptoEngine(profile("AES", "CBC", CryptoProfile.Padding.ZERO,
                CryptoProfile.Encoding.HEX, KEY, new byte[0])).encryptText("x"));
        assertThrows(IllegalArgumentException.class, () -> new CryptoEngine(legacy()).decryptText("ENC:not-hex"));
        assertThrows(IllegalArgumentException.class, () -> new CryptoEngine(legacy()).decryptText("ENC:00"));
    }

    @Test void utf16ZeroPaddingDoesNotTruncateLastCodeUnit() {
        var settings = new CryptoProfile("AES", "ECB", CryptoProfile.Padding.ZERO, CryptoProfile.Encoding.HEX,
                StandardCharsets.UTF_16LE, "ENC:", KEY, new byte[0], new byte[0], CryptoProfile.defaults().pathPattern());
        var engine = new CryptoEngine(settings);
        assertEquals("ending A", engine.decryptText(engine.encryptText("ending A")));
    }

    @Test void gcmKnownAnswer() {
        var engine = new CryptoEngine(profile("AES", "GCM", CryptoProfile.Padding.NONE, CryptoProfile.Encoding.HEX, new byte[16], new byte[12]));
        assertArrayEquals(HexFormat.of().parseHex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"), engine.encrypt(new byte[16]));
    }
}
