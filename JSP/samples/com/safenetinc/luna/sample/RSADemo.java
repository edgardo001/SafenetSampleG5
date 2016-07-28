// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 This example illustrates how to Generate RSA key pairs, Sign/Verify and
 Encrypt/Decrypt with the generated KeyPair.
 */

/**
 * RSADemo This example illustrates how to generate RSA key pairs
 */
public class RSADemo {
    public static void main(String[] args) {
        // Login to the HSM
        HSM_Manager.hsmLogin();

        KeyPairGenerator keyGen = null;
        KeyPair RSAkeypair = null;
        try {
            // Generate an 1024-bit RSA KeyPair
            /*
             * The KeyPairGenerator class is used to determine the type of
             * KeyPair being generated. The most common options for this are RSA
             * or DSA.
             * 
             * For more information concerning the algorithms available in the
             * Luna provider please see the Luna Development Guide. For more
             * information concerning other providers, please read the
             * documentation available for the provider in question.
             */
            System.out.println("Generating RSA Keypair");
            /*
             * The KeyPairGenerator.getInstance method also supports specifying
             * providers as a parameter to the method.
             * 
             * keyGen = KeyPairGenerator.getInstance("RSA", "Luna"); - which
             * specifies the Luna provider for the RSA KeyPair generation or
             * keyGen = KeyPairGenerator.getInstance("RSA", "SUN"); - which uses
             * the Sun provider for the RSA KeyPair generation
             * 
             * Many other methods will allow you to specify the provider as a
             * parameter. Please see the Sun JDK class reference at
             * http://java.sun.org for more information.
             */
            keyGen = KeyPairGenerator.getInstance("RSA", "LunaProvider");
            keyGen.initialize(1024);
            RSAkeypair = keyGen.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Exception during Key Generation - "
                    + e.getMessage());
            System.exit(1);
        }

        // Initialize the Cipher for Encryption and encrypt the message
        String starttext = "Some Text to Encrypt and Sign as an Example";
        byte[] bytes = starttext.getBytes();
        System.out.println("PlainText = " + starttext);

        Cipher rsaCipher = null;
        try {
            // Initialize the Cipher
            /*
             * There are other RSA Ciphers available for use: RSA/NONE/PKCS1v1_5
             * RSA/NONE/OAEPWithSHA1andMGF1Padding
             * 
             * For a full list of supported Ciphers in the Luna provider
             * please see the Luna Development Guide.
             * 
             * For a list of supported Ciphers in alternate providers please see
             * the documentation of the provider in question.
             */
            rsaCipher = Cipher.getInstance("RSA/NONE/NoPadding", "LunaProvider");
            rsaCipher.init(Cipher.ENCRYPT_MODE, RSAkeypair.getPublic());
        } catch (Exception e) {
            System.out.println("Exception in Cipher Initialization - "
                    + e.getMessage());
            System.exit(1);
        }

        byte[] encryptedbytes = null;
        try {
            // Encrypt the message
            /*
             * Encrypt/Decrypt operations can be performed in one of two ways 1.
             * Singlepart 2. Multipart
             * 
             * To perform a singlepart encrypt/decrypt operation use the
             * following example. Multipart encrypt/decrypt operations require
             * use of the Cipher.update() and Cipher.doFinal() methods.
             * 
             * For more information please see the class documentation for the
             * java.cryptox.Cipher class with respect to the version of the JDK
             * you are using.
             */

            System.out.println("Encrypting Text");
            encryptedbytes = rsaCipher.doFinal(bytes);
        } catch (Exception e) {
            System.out.println("Exception during Encryption - "
                    + e.getMessage());
            System.exit(1);
        }

        try {
            // Decrypt the text
            System.out.println("Decrypting Text");
            rsaCipher.init(Cipher.DECRYPT_MODE, RSAkeypair.getPrivate());
            byte[] decryptedbytes = rsaCipher.doFinal(encryptedbytes);

            /*
             * Basic RSA without padding will return a value of the same length
             * as the key's bitlength.  If the actual decrypted result is smaller,
             * it will be prepended with 00 bytes.  We filter the decrypted
             * result through a BigInteger to trim those zeros; this gives us
             * back legible text when used in the String constructor.
             */ 
            String endtext = new String( new BigInteger(decryptedbytes).toByteArray() );
            System.out.println("Decrypted PlainText = " + endtext);
            
        } catch (Exception e) {
            System.out.println("Exception during Decryption - "
                    + e.getMessage());
            System.exit(1);
        }

        Signature rsasig = null;
        byte[] signature = null;
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
            rsasig = Signature.getInstance("SHA256withRSA");
            rsasig.initSign(RSAkeypair.getPrivate());
            rsasig.update(bytes);
            signature = rsasig.sign();
        } catch (Exception e) {
            System.out.println("Exception during Signing - " + e.getMessage());
            System.exit(1);
        }

        try {
            // Verify the signature
            System.out.println("Verifying signature");
            rsasig.initVerify(RSAkeypair.getPublic());
            rsasig.update(bytes);
            boolean verifies = rsasig.verify(signature);
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
