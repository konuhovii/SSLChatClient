import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.logging.Logger;

public class SSLChatClient {
    private static final char[] PASSWORD = "passphrase".toCharArray();
    private static final String KEYSTORE_TYPE = "JKS";
    private static final String ALGORITHM = "SunX509";
    private static final String SSL_PROTOCOL = "TLSv1";
    private static final Logger LOG = Logger.getGlobal();
    private final String SERVER_HOST = "127.0.0.1";
    private final int SERVER_PORT = 2626;
    private static final String KEYSTORE_PATH = "C:\\Users\\admin\\IdeaProjects\\HTTPSServer\\test.jks";

    public static void main(String[] args) {
        LOG.info("Starting SSLChatClient...");
        SSLChatClient client = new SSLChatClient();
        client.run();
    }

    // Create and initialize the SSLContext
    private SSLContext createSSLContext() {
        try {
            LOG.info("Creating SSLContext...");
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(new FileInputStream(KEYSTORE_PATH), PASSWORD);

            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(ALGORITHM);
            keyManagerFactory.init(keyStore, PASSWORD);
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(ALGORITHM);
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
            sslContext.init(km, tm, null);

            LOG.info("SSLContext created successfully.");
            return sslContext;
        } catch (Exception ex) {
            LOG.warning("SSLContext create failed.");
            ex.printStackTrace();
        }
        LOG.warning("SSLContext create failed.");
        return null;
    }

    // Start to run the server
    public void run() {
        SSLContext sslContext = createSSLContext();

        try {
            LOG.info("Creating SSLSocket...");
            // Create socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create socket
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(SERVER_HOST, SERVER_PORT);

            LOG.info("SSLSocket created.");
            new ClientThread(sslSocket).start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket to server
    static class ClientThread extends Thread {
        private SSLSocket sslSocket;
        private DataOutputStream outputStream;

        ClientThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            LOG.info("SSLSocket enabling cipher suites.");
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                LOG.info("SSLSocket handshaking with server...");
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                System.out.println("SSLSession :");
                System.out.println("Protocol : " + sslSession.getProtocol());
                System.out.println("Cipher suite : " + sslSession.getCipherSuite());

                // Start handling application content
                LOG.info("Listening input stream.");
                new Thread(new InputStreamListener(sslSocket)).start();

                //deal with output stream
                LOG.info("Listening output stream.");
                outputStream = new DataOutputStream(sslSocket.getOutputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

                String line;
                while ((line = br.readLine()) != null && !sslSocket.isClosed()) {
                    System.out.println("Client>>" + line);
                    outputStream.writeUTF(line);
                    outputStream.flush();
                    if (line.trim().equals("HTTP/1.1 200\r\n")) {
                        break;
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            } finally {
                try {
                    outputStream.close();
                    sslSocket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static class InputStreamListener implements Runnable {

        private SSLSocket sslSocket;

        public InputStreamListener(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        @Override
        public void run() {
            DataInputStream dataInputStream = null;
            try {
                dataInputStream = new DataInputStream(sslSocket.getInputStream());
                while (!sslSocket.isClosed()) {
                    System.out.println("Server>>" + dataInputStream.readUTF());
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    dataInputStream.close();
                    sslSocket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}