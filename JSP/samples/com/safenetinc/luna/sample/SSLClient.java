// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;


/**
 * This sample demonstrates using the Luna provider for SSL client operation.
 * Before running the sample, you will need to do the following:
 * <p>
 * Set up a Luna keystore file for your slot.  This example assumes that
 * you're using slot 1, with a password of userpin.  Create a file called
 * "lunassl.ks" containing the following line (without quotes): "slot:1".
 * <p>
 * Retrieve the server cert and use keytool to import it into the HSM:
 * keytool -importcert -v -storetype luna -keystore lunassl.ks -storepass userpin
 *    -alias [server] -file [server crt]
 * <p> 
 * If you don't do this before running the application, the SSL connection will
 * the application will get an SSLHandshakeException when it can't find any
 * trusted certificates.
 */
public class SSLClient {

    // Configure these as required.
    private static final int slot = 0;
    private static final String passwd = "userpin";

    public static class NullHostnameVerifier implements HostnameVerifier {
        @SuppressWarnings("unused")
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("\tUsage:   'java SSLClient <https_url>'");
            System.exit(-1);
        }

        // load the keystore
        KeyStore ks = KeyStore.getInstance("luna");
        FileInputStream ksFile = new FileInputStream("lunassl.ks");
        char[] ksPass = passwd.toCharArray();
        ks.load(ksFile, ksPass);
        
        // init key manager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, ksPass);
        // now trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // init ssl context
        SSLContext sslctx = SSLContext.getInstance("SSLv3");
        sslctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        // set the default socket factory
        SSLSocketFactory ssf = sslctx.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(ssf);
        HttpsURLConnection.setDefaultHostnameVerifier(new NullHostnameVerifier());

        // form URL object from argument
        String urlString = args[0];
        URL url = new URL(urlString);

        // open the connection
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        InputStream is = connection.getInputStream();
        int numBytesRead = -1;
        byte[] buffer = new byte[8192];
        while ((numBytesRead = is.read(buffer)) >= 0) {
            System.out.println(new String(buffer, 0, numBytesRead));
        }
    }
}
