package local.messagecrypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public record CryptoProfile(String algorithm, String mode, Padding padding, Encoding encoding,
                            Charset charset, String prefix, byte[] key, byte[] iv, byte[] aad,
                            String pathPattern) {
    public enum Padding { ZERO, PKCS7, NONE }
    public enum Encoding { HEX, BASE64, UTF8 }

    public CryptoProfile {
        key = key.clone();
        iv = iv.clone();
        aad = aad.clone();
    }

    @Override public byte[] key() { return key.clone(); }
    @Override public byte[] iv() { return iv.clone(); }
    @Override public byte[] aad() { return aad.clone(); }

    public static CryptoProfile defaults() {
        return new CryptoProfile("AES", "ECB", Padding.ZERO, Encoding.HEX,
                StandardCharsets.UTF_8, "ENC:", new byte[0], new byte[0], new byte[0],
                "(?i)/(MessageHandler|RealtimeHandler)(\\.aspx)?(?:\\?|$)");
    }
}
