package local.messagecrypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

public final class CryptoEngine {
    private final CryptoProfile profile;

    public CryptoEngine(CryptoProfile profile) { this.profile = profile; }

    public void validate() {
        if (!profile.algorithm().equals("AES") && !profile.algorithm().equals("DESede"))
            throw new IllegalArgumentException("Algorithm must be AES or DESede.");
        int size = profile.key().length;
        if (size == 0) throw new IllegalArgumentException("Configure a shared key first.");
        if (profile.algorithm().equals("AES") ? size != 16 && size != 24 && size != 32 : size != 24)
            throw new IllegalArgumentException("AES requires 16/24/32 key bytes; DESede requires 24.");
        switch (profile.mode()) {
            case "ECB" -> { }
            case "CBC" -> {
                if (profile.iv().length != blockSize()) throw new IllegalArgumentException("CBC requires a block-sized IV.");
            }
            case "GCM" -> {
                if (!profile.algorithm().equals("AES") || profile.padding() != CryptoProfile.Padding.NONE || profile.iv().length != 12)
                    throw new IllegalArgumentException("GCM requires AES, NONE padding, and a 12-byte nonce.");
            }
            default -> throw new IllegalArgumentException("Mode must be ECB, CBC or GCM.");
        }
        if (!profile.mode().equals("GCM") && profile.aad().length != 0)
            throw new IllegalArgumentException("AAD is supported only for GCM.");
        if (profile.encoding() == CryptoProfile.Encoding.UTF8)
            throw new IllegalArgumentException("Ciphertext encoding must be HEX or BASE64.");
    }

    private int blockSize() { return profile.algorithm().equals("AES") ? 16 : 8; }

    private byte[] transform(byte[] input, boolean encrypt) {
        validate();
        try {
            String padding = profile.padding() == CryptoProfile.Padding.PKCS7 ? "PKCS5Padding" : "NoPadding";
            Cipher cipher = Cipher.getInstance(profile.algorithm() + "/" + profile.mode() + "/" + padding);
            var key = new SecretKeySpec(profile.key(), profile.algorithm());
            int operation = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if (profile.mode().equals("GCM")) cipher.init(operation, key, new GCMParameterSpec(128, profile.iv()));
            else if (profile.mode().equals("CBC")) cipher.init(operation, key, new IvParameterSpec(profile.iv()));
            else cipher.init(operation, key);
            if (profile.aad().length != 0) cipher.updateAAD(profile.aad());
            if (encrypt && profile.padding() == CryptoProfile.Padding.ZERO) {
                int size = input.length == 0 ? 0 : Math.addExact(input.length, blockSize() - 1) / blockSize() * blockSize();
                input = Arrays.copyOf(input, size);
            }
            return cipher.doFinal(input);
        } catch (GeneralSecurityException | ArithmeticException error) {
            throw new IllegalArgumentException("Cipher operation failed; check key, mode, padding, IV and input length.", error);
        }
    }

    public byte[] encrypt(byte[] input) { return transform(input, true); }
    public byte[] decrypt(byte[] input) {
        byte[] result = transform(input, false);
        if (profile.padding() == CryptoProfile.Padding.ZERO) {
            int end = result.length;
            while (end > 0 && result[end - 1] == 0) end--;
            result = Arrays.copyOf(result, end);
        }
        return result;
    }

    public String encryptText(String input) {
        try {
            var buffer = profile.charset().newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(input));
            byte[] plain = new byte[buffer.remaining()];
            buffer.get(plain);
            return profile.prefix() + encode(encrypt(plain), profile.encoding());
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("Plaintext is not representable in the selected charset.", error);
        }
    }

    public String decryptText(String input) {
        if (!input.startsWith(profile.prefix())) throw new IllegalArgumentException("Ciphertext prefix does not match.");
        byte[] output = transform(decode(input.substring(profile.prefix().length()), profile.encoding()), false);
        try {
            String result = profile.charset().newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output)).toString();
            // Strip decoded NUL characters rather than bytes, preserving UTF-16 code units.
            if (profile.padding() == CryptoProfile.Padding.ZERO) {
                int end = result.length();
                while (end > 0 && result.charAt(end - 1) == 0) end--;
                result = result.substring(0, end);
            }
            return result;
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("Decrypted bytes are invalid for the selected charset; check the key.", error);
        }
    }

    public static byte[] decode(String text, CryptoProfile.Encoding encoding) {
        try {
            return switch (encoding) {
                case HEX -> HexFormat.of().parseHex(text);
                case BASE64 -> Base64.getDecoder().decode(text);
                case UTF8 -> text.getBytes(StandardCharsets.UTF_8);
            };
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("Invalid " + encoding + " encoding.");
        }
    }

    public static String encode(byte[] data, CryptoProfile.Encoding encoding) {
        return switch (encoding) {
            case HEX -> HexFormat.of().withUpperCase().formatHex(data);
            case BASE64 -> Base64.getEncoder().encodeToString(data);
            case UTF8 -> new String(data, StandardCharsets.UTF_8);
        };
    }
}
