package local.messagecrypto;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.concurrent.Executors;

/** Loopback-only synthetic protocol fixture, independent of Burp or any real application. */
public final class DemoServer {
    public static final String DEMO_KEY_HEX = "000102030405060708090a0b0c0d0e0f";

    public static void main(String[] args) throws Exception {
        var profile = new CryptoProfile("AES", "ECB", CryptoProfile.Padding.ZERO, CryptoProfile.Encoding.HEX,
                StandardCharsets.UTF_8, "ENC:", HexFormat.of().parseHex(DEMO_KEY_HEX), new byte[0], new byte[0],
                CryptoProfile.defaults().pathPattern());
        var engine = new CryptoEngine(profile);
        String sample = "action=createetk&user=demo&password=" + URLEncoder.encode(engine.encryptText("demo-password"), StandardCharsets.UTF_8);
        if (args.length > 0 && args[0].equals("--sample")) {
            System.out.println("POST /MessageHandler HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: "
                    + sample.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + sample);
            return;
        }
        int port = args.length == 0 ? 18080 : Integer.parseInt(args[0]);
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.createContext("/MessageHandler", exchange -> {
            String response;
            int status;
            try {
                if (!exchange.getRequestMethod().equals("POST")) throw new IllegalArgumentException();
                byte[] data = exchange.getRequestBody().readNBytes(1024 * 1024 + 1);
                if (data.length > 1024 * 1024) throw new IllegalArgumentException();
                String plaintext = "demo-response";
                for (String part : new String(data, StandardCharsets.UTF_8).split("&")) {
                    int equals = part.indexOf('=');
                    if (equals >= 0 && URLDecoder.decode(part.substring(0, equals), StandardCharsets.UTF_8).equals("password"))
                        plaintext = engine.decryptText(URLDecoder.decode(part.substring(equals + 1), StandardCharsets.UTF_8));
                }
                response = "<Response><Status>ok</Status><Echo encrypted=\"true\">" + engine.encryptText(plaintext) + "</Echo></Response>";
                status = 200;
            } catch (IllegalArgumentException error) {
                response = "<Response><Status>fail</Status><Errors>Invalid synthetic request</Errors></Response>";
                status = 400;
            }
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/xml; charset=UTF-8");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        System.out.println("Synthetic demo listening at http://127.0.0.1:" + port + "/MessageHandler");
        System.out.println("Demo settings: AES / ECB / ZERO / HEX / UTF-8 / ENC:, key encoding HEX: " + DEMO_KEY_HEX);
        System.out.println("Sample form body: " + sample);
    }
}
