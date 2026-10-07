package local.messagecrypto;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import javax.swing.JPanel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BurpEditorTest {
    private MockedStatic<ByteArray> factory;
    private MontoyaApi api;
    private RawEditor raw;
    private HttpRequest original;
    private HttpRequestResponse message;
    private EditorCreationContext context;
    private AtomicReference<CryptoProfile> profiles;
    private final AtomicReference<byte[]> contents = new AtomicReference<>();
    private final AtomicBoolean modified = new AtomicBoolean();

    private static ByteArray array(byte[] value) {
        var bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.clone());
        return bytes;
    }
    private static HttpHeader header(String name, String value) {
        var header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name); when(header.value()).thenReturn(value);
        return header;
    }

    @BeforeEach void setup() {
        factory = mockStatic(ByteArray.class);
        factory.when(() -> ByteArray.byteArray(any(byte[].class))).thenAnswer(call -> array((byte[])call.getRawArguments()[0]));
        factory.when(() -> ByteArray.byteArray(anyString())).thenAnswer(call -> array(((String)call.getArgument(0)).getBytes(StandardCharsets.UTF_8)));
        api = mock(MontoyaApi.class);
        var ui = mock(UserInterface.class);
        when(api.userInterface()).thenReturn(ui);
        raw = mock(RawEditor.class);
        when(ui.createRawEditor(any(EditorOptions[].class))).thenReturn(raw);
        when(raw.uiComponent()).thenReturn(new JPanel());
        when(raw.selection()).thenReturn(Optional.empty());
        when(raw.isModified()).thenAnswer(call -> modified.get());
        when(raw.getContents()).thenAnswer(call -> array(contents.get()));
        doAnswer(call -> { contents.set(((ByteArray)call.getArgument(0)).getBytes()); modified.set(false); return null; })
                .when(raw).setContents(any(ByteArray.class));
        context = mock(EditorCreationContext.class);
        when(context.editorMode()).thenReturn(EditorMode.DEFAULT);
        profiles = new AtomicReference<>(CryptoEngineTest.legacy());
        original = mock(HttpRequest.class);
        when(original.path()).thenReturn("/MessageHandler");
        var headers = List.of(header("Content-Type", "application/x-www-form-urlencoded"));
        var body = array("action=routemessage&value=old".getBytes(StandardCharsets.UTF_8));
        when(original.headers()).thenReturn(headers);
        when(original.body()).thenReturn(body);
        message = mock(HttpRequestResponse.class);
        when(message.request()).thenReturn(original);
    }

    @AfterEach void close() { factory.close(); }

    @Test void unchangedEditorReturnsOriginalHttpObject() {
        var editor = new RequestEditor(api, context, profiles);
        assertTrue(editor.isEnabledFor(message));
        editor.setRequestResponse(message);
        assertSame(original, editor.getRequest());
        verify(original, never()).withBody(any(ByteArray.class));
    }

    @Test void editedBodyGoesThroughBurpsWithBodyApi() throws Exception {
        var editor = new RequestEditor(api, context, profiles);
        editor.setRequestResponse(message);
        var json = (ObjectNode)new ObjectMapper().readTree(contents.get());
        ((ObjectNode)json.withArray("fields").get(1)).put("value", "new");
        contents.set(json.toString().getBytes(StandardCharsets.UTF_8)); modified.set(true);
        var updated = mock(HttpRequest.class);
        when(original.withBody(any(ByteArray.class))).thenAnswer(call -> {
            assertEquals("action=routemessage&value=new", new String(((ByteArray)call.getArgument(0)).getBytes(), StandardCharsets.UTF_8));
            return updated;
        });
        assertSame(updated, editor.getRequest());
    }

    @Test void invalidJsonReturnsOriginalRatherThanSendingPartialEdits() {
        var editor = new RequestEditor(api, context, profiles);
        editor.setRequestResponse(message);
        contents.set("broken".getBytes(StandardCharsets.UTF_8)); modified.set(true);
        assertSame(original, editor.getRequest());
        verify(original, never()).withBody(any(ByteArray.class));
    }

    @Test void readOnlyEditorNeverRewrites() {
        when(context.editorMode()).thenReturn(EditorMode.READ_ONLY);
        var editor = new RequestEditor(api, context, profiles);
        editor.setRequestResponse(message);
        contents.set("edited".getBytes(StandardCharsets.UTF_8)); modified.set(true);
        assertFalse(editor.isModified());
        assertSame(original, editor.getRequest());
    }

    @Test void scopeAndCompressionAreRespected() {
        var editor = new RequestEditor(api, context, profiles);
        when(original.path()).thenReturn("/unrelated");
        assertFalse(editor.isEnabledFor(message));
        when(original.path()).thenReturn("/RealtimeHandler.aspx");
        var headers = List.of(header("Content-Encoding", "gzip"));
        when(original.headers()).thenReturn(headers);
        assertFalse(editor.isEnabledFor(message));
    }
}
