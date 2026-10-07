package local.messagecrypto;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.Charset;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public final class ConfigPanel extends JPanel {
    private final AtomicReference<CryptoProfile> profile;
    private final JComboBox<String> algorithm = new JComboBox<>(new String[] {"AES", "DESede"});
    private final JComboBox<String> mode = new JComboBox<>(new String[] {"ECB", "CBC", "GCM"});
    private final JComboBox<CryptoProfile.Padding> padding = new JComboBox<>(CryptoProfile.Padding.values());
    private final JComboBox<CryptoProfile.Encoding> encoding = new JComboBox<>(new CryptoProfile.Encoding[] {CryptoProfile.Encoding.HEX, CryptoProfile.Encoding.BASE64});
    private final JComboBox<CryptoProfile.Encoding> keyEncoding = new JComboBox<>(new CryptoProfile.Encoding[] {CryptoProfile.Encoding.UTF8, CryptoProfile.Encoding.HEX, CryptoProfile.Encoding.BASE64});
    private final JComboBox<CryptoProfile.Encoding> ivEncoding = new JComboBox<>(new CryptoProfile.Encoding[] {CryptoProfile.Encoding.HEX, CryptoProfile.Encoding.BASE64, CryptoProfile.Encoding.UTF8});
    private final JPasswordField key = new JPasswordField(32);
    private final JTextField iv = new JTextField(32);
    private final JTextField aad = new JTextField(32);
    private final JTextField prefix = new JTextField("ENC:", 20);
    private final JTextField charset = new JTextField("UTF-8", 20);
    private final JTextField paths = new JTextField(CryptoProfile.defaults().pathPattern(), 48);
    private final JTextArea input = new JTextArea(6, 60);
    private final JTextArea output = new JTextArea(6, 60);
    private final JLabel status = new JLabel("Enter a shared key, then Apply. Keys are not saved by this extension.");

    public ConfigPanel(AtomicReference<CryptoProfile> profile) {
        super(new BorderLayout(8, 8));
        this.profile = profile;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        var settings = new JPanel(new GridBagLayout());
        var row = new GridBagConstraints();
        row.insets = new Insets(3, 4, 3, 4); row.fill = GridBagConstraints.HORIZONTAL;
        addRow(settings, row, 0, "Algorithm / mode / padding", group(algorithm, mode, padding));
        addRow(settings, row, 1, "Ciphertext encoding / prefix", group(encoding, prefix));
        addRow(settings, row, 2, "Shared key / key encoding", group(key, keyEncoding));
        addRow(settings, row, 3, "IV or GCM nonce / encoding", group(iv, ivEncoding));
        addRow(settings, row, 4, "GCM AAD (UTF-8, optional)", aad);
        addRow(settings, row, 5, "Plaintext charset", charset);
        addRow(settings, row, 6, "Request path regex (editor scope)", paths);
        var apply = new JButton("Apply configuration");
        var clear = new JButton("Clear shared key and scratchpad");
        apply.addActionListener(event -> apply());
        clear.addActionListener(event -> clearKey());
        addRow(settings, row, 7, "", group(apply, clear));
        addRow(settings, row, 8, "", new JLabel("ZERO = zero padding; PKCS7 = Java PKCS5Padding; NONE = no padding."));
        addRow(settings, row, 9, "", new JLabel("Existing editor tabs keep their captured profile. Reopen a message after changing settings."));
        add(settings, BorderLayout.NORTH);

        output.setEditable(false);
        input.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        output.setFont(input.getFont());
        var scratch = new JPanel(new BorderLayout(4, 4));
        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(input), new JScrollPane(output));
        split.setResizeWeight(0.5);
        scratch.add(split, BorderLayout.CENTER);
        var encrypt = new JButton("Encrypt using applied profile");
        var decrypt = new JButton("Decrypt using applied profile");
        encrypt.addActionListener(event -> convert(true));
        decrypt.addActionListener(event -> convert(false));
        scratch.add(group(encrypt, decrypt), BorderLayout.NORTH);
        scratch.setBorder(BorderFactory.createTitledBorder("Manual conversion scratchpad (input above, output below)"));
        add(scratch, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
    }

    private void apply() {
        try {
            String secret = new String(key.getPassword());
            var candidate = new CryptoProfile((String)algorithm.getSelectedItem(), (String)mode.getSelectedItem(),
                    (CryptoProfile.Padding)padding.getSelectedItem(), (CryptoProfile.Encoding)encoding.getSelectedItem(),
                    Charset.forName(charset.getText().strip()), prefix.getText(),
                    CryptoEngine.decode(secret, (CryptoProfile.Encoding)keyEncoding.getSelectedItem()),
                    CryptoEngine.decode(iv.getText(), (CryptoProfile.Encoding)ivEncoding.getSelectedItem()),
                    aad.getText().getBytes(java.nio.charset.StandardCharsets.UTF_8), paths.getText());
            Pattern.compile(candidate.pathPattern());
            if (candidate.key().length > 0) new CryptoEngine(candidate).validate();
            profile.set(candidate);
            status.setText("Configuration applied. Reopen messages to use it; no automatic network rewriting is enabled.");
        } catch (IllegalArgumentException error) { status.setText("Not applied: " + error.getMessage()); }
    }

    private void convert(boolean encrypt) {
        try {
            var engine = new CryptoEngine(profile.get());
            output.setText(encrypt ? engine.encryptText(input.getText()) : engine.decryptText(input.getText()));
            status.setText("Conversion complete using the applied profile.");
        } catch (IllegalArgumentException error) { output.setText(""); status.setText("Conversion failed: " + error.getMessage()); }
    }

    public void clearKey() {
        key.setText(""); input.setText(""); output.setText("");
        var current = profile.get();
        profile.set(new CryptoProfile(current.algorithm(), current.mode(), current.padding(), current.encoding(),
                current.charset(), current.prefix(), new byte[0], current.iv(), current.aad(), current.pathPattern()));
        status.setText("Shared key cleared from active configuration. Existing message snapshots retain their own configuration.");
    }

    private static JPanel group(Component... components) {
        var panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (var component : components) panel.add(component);
        return panel;
    }

    private static void addRow(JPanel panel, GridBagConstraints c, int index, String label, Component component) {
        c.gridy = index; c.gridx = 0; c.weightx = 0;
        panel.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1;
        panel.add(component, c);
    }
}
