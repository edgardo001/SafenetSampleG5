// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaUtils;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


/**
 * This sample demonstrates RSA encryption with padding.
 */
public class RsaencPAD {

    // Configure these as required.
    private static final int slot = 0;
    private static final String passwd = "userpin";

    public static void main(String args[]) {
        LunaSlotManager manager;
        manager = LunaSlotManager.getInstance();

        try {
            manager.login(slot, passwd); // log in to the designated slot
        } catch (Exception e) {
            System.out.println("Exception during login");
        }

        KeyPairGenerator kpg = null;
        KeyPair myPair = null;
        try {
            // ********************************************
            // need to make an rsa keypair in software.
            // ********************************************
            kpg = KeyPairGenerator.getInstance("RSA", "LunaProvider");
            kpg.initialize(1024);
            myPair = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Exception generating keypair");
            e.printStackTrace();
        }

        // ********************************************
        // encrypt something
        // ********************************************
        byte[] bytes = "10000000008".getBytes();
        byte[] encrypted = null;
        try {
            Cipher myCipher = Cipher.getInstance("RSA/NONE/PKCS1v1_5", "LunaProvider");
            myCipher.init(Cipher.ENCRYPT_MODE, myPair.getPublic());
            encrypted = myCipher.doFinal(bytes);
        } catch (Exception e) {
            System.out.println("Exception ciphering the data");
            e.printStackTrace();
        }

        // ********************************************
        // decrypt the encrypted value
        // ********************************************
        byte[] decrypted = null;
        try {
            Cipher myCipher = Cipher.getInstance("RSA/NONE/PKCS1v1_5",
            "LunaProvider");
            myCipher.init(Cipher.DECRYPT_MODE, myPair.getPrivate());
            decrypted = myCipher.doFinal(encrypted);
        } catch (Exception e) {
            System.out.println("Exception deciphering the data");
            e.printStackTrace();
        }

        System.out.println("\n\n-----------------------");
        System.out.println("original: ");
        System.out.println("  Size:    " + bytes.length);
        System.out.println("  Content: " + LunaUtils.getHexString(bytes, true));
        System.out.println("encrypted: ");
        System.out.println("  Size:    " + encrypted.length);
        System.out.println("  Content: " + LunaUtils.getHexString(encrypted, true));
        System.out.println("decrypted: ");
        System.out.println("  Size:    " + decrypted.length);
        System.out.println("  Content: " + LunaUtils.getHexString(decrypted, true));
        System.out.println("\n\n-----------------------");

        if (java.util.Arrays.equals(bytes, decrypted)) {
            System.out.println("Decryption was successful");
        } else
            System.out.println("*** decryption failed");
        System.out.println("-----------------------\n\n");
    }
}
