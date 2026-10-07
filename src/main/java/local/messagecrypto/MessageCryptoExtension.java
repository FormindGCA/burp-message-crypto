package local.messagecrypto;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

public final class MessageCryptoExtension implements BurpExtension {
    @Override public void initialize(MontoyaApi api) {
        api.extension().setName("BO Message Crypto");
        var profiles = new AtomicReference<>(CryptoProfile.defaults());
        var panel = new ConfigPanel(profiles);
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("Message Crypto", panel);
        api.userInterface().registerHttpRequestEditorProvider(context -> new RequestEditor(api, context, profiles));
        api.userInterface().registerHttpResponseEditorProvider(context -> new ResponseEditor(api, context, profiles));
        api.extension().registerUnloadingHandler(() -> SwingUtilities.invokeLater(panel::clearKey));
        api.logging().logToOutput("BO Message Crypto loaded. Configure the key in the suite tab. Only explicit editor edits alter HTTP messages.");
    }
}
