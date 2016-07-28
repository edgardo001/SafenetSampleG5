// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import com.safenetinc.luna.provider.LunaCertificateX509;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * This example illustrates how to generate ECDSA key pairs
 * The pair will then be used to generate a self-signed certificate
 * and to sign/verify some data.
 */
public class ECDSADemo {
    public static void main(String[] args) {
        // Login to the HSM
        HSM_Manager.hsmLogin();

        KeyPairGenerator keyGen = null;
        KeyPair keyPair = null;
        try {
            // Generate an ECDSA KeyPair
            /*
             * The KeyPairGenerator class is used to determine the type of
             * KeyPair being generated. 
             * 
             * For more information concerning the algorithms available in the
             * Luna provider please see the Luna Development Guide. For more
             * information concerning other providers, please read the
             * documentation available for the provider in question.
             */
            System.out.println("Generating ECDSA Keypair");
            /*
             * The KeyPairGenerator.getInstance method also supports specifying
             * providers as a parameter to the method.
             * 
             * Many other methods will allow you to specify the provider as a
             * parameter. Please see the Sun JDK class reference at
             * http://java.sun.org for more information.
             */
            keyGen = KeyPairGenerator.getInstance("ECDSA", "LunaProvider");
            /*
             * ECDSA keys need to know what curve to use.
             * 
             * If you know the curve ID to use you can specify it directly.
             * In the Luna Provider all supported curves are defined
             * in LunaECCurve
             */
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("c2pnb304w1");
            keyGen.initialize(ecSpec);
            keyPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Exception during Key Generation - "
                    + e.getMessage());
            System.exit(1);
        }

        //generate a self-signed ECDSA certificate.
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 1000000000);
        BigInteger serialNum = new BigInteger("123456");
        LunaCertificateX509 cert = null;
        try {
            cert = LunaCertificateX509.SelfSign(keyPair, "CN=ECDSA Sample Cert", serialNum, notBefore, notAfter);
        } catch (InvalidKeyException ike) {
            System.out.println("Unexpected InvalidKeyException while generating cert.");
            System.exit(-1);
        } catch (CertificateEncodingException cee) {
            System.out.println("Unexpected CertificateEncodingException while generating cert.");
            System.exit(-1);
        }

        byte[] bytes = "Some Text to Sign as an Example".getBytes();
        System.out.println("PlainText = " + com.safenetinc.luna.LunaUtils.getHexString(bytes, true));

        Signature ecdsaSig = null;
        byte[] signatureBytes = null;
        try {
            // Create a Signature Object and sign the encrypted text
            /*
             * Sign/Verify operations like Encrypt/Decrypt operations can be
             * performed in either singlepart or multipart steps.
             * 
             * Single part Signing and Verify examples are given in this code.
             * Multipart signatures use the Signature.update() method to load
             * all the bytes and then invoke the Signature.sign() method to get
             * the result.
             * 
             * For more information please see the class documentation for the
             * java.security.Signature class with respect to the version of the
             * JDK you are using.
             */
            System.out.println("Signing encrypted text");
            ecdsaSig = Signature.getInstance("ECDSA");
            ecdsaSig.initSign(keyPair.getPrivate());
            ecdsaSig.update(bytes);
            signatureBytes = ecdsaSig.sign();
        } catch (Exception e) {
            System.out.println("Exception during Signing - " + e.getMessage());
            System.exit(1);
        }

        try {
            // Verify the signature
            System.out.println("Verifying signature");
            ecdsaSig.initVerify(cert);
            ecdsaSig.update(bytes);
            boolean verifies = ecdsaSig.verify(signatureBytes);
            if (verifies == true) {
                System.out.println("Signature passed verification");
            } else {
                System.out.println("Signature failed verification");
            }
        } catch (Exception e) {
            System.out.println("Exception during Verification - "
                    + e.getMessage());
            System.exit(1);
        }

        // Logout of the token
        HSM_Manager.hsmLogout();
    }
}
