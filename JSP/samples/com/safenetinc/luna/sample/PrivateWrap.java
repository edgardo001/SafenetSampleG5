// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import com.safenetinc.luna.LunaAPI;
import com.safenetinc.luna.LunaCryptokiException;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.provider.key.LunaPrivateKeyRsa;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

/**
 * This sample demonstrates how to wrap a private key.
 * This sample is only applicable to HSMs with Key Export configurations  
 */

public class PrivateWrap {

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
            System.exit(-1);
        }

        KeyPairGenerator kpg = null;
        KeyPair myPair = null;
        KeyGenerator kg = null;
        SecretKey aesKey = null;

        try {
            // ********************************************
            // need to make an rsa keypair.
            // ********************************************
            kpg = KeyPairGenerator.getInstance("RSA", "LunaProvider");
            kpg.initialize(1024);
            myPair = kpg.generateKeyPair();

            // ********************************************
            // make the wrapping key. AES
            // ********************************************
            kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            aesKey = kg.generateKey();

        } catch (Exception e) {
            System.out.println("Exception generating keys");
            e.printStackTrace();
            System.exit(1);
        }

        // ********************************************
        // encrypt something
        // ********************************************
        byte[] bytes = "Encrypt Me!".getBytes();
        byte[] encrypted = null;
        try {
            Cipher myCipher = Cipher.getInstance("RSA/NONE/PKCS1v1_5", "LunaProvider");
            myCipher.init(Cipher.ENCRYPT_MODE, myPair.getPublic());
            encrypted = myCipher.doFinal(bytes);

        } catch (Exception e) {
            System.out.println("Exception ciphering the data");
            e.printStackTrace();
            System.exit(1);
        }

        // ********************************************
        // try to wrap the private key
        // ********************************************
        byte[] wrappedKey = null;
        try {
            Cipher myWrapper = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
            byte[] ivBytes = { (byte) 65, (byte) 66, (byte) 67, (byte) 68,
                    (byte) 69, (byte) 70, (byte) 71, (byte) 72, (byte) 73,
                    (byte) 74, (byte) 75, (byte) 76, (byte) 77, (byte) 78,
                    (byte) 79, (byte) 80 };
            AlgorithmParameters mAlgParams = AlgorithmParameters.getInstance(
                    "IV", "LunaProvider");
            mAlgParams.init(new IvParameterSpec(ivBytes));
            myWrapper.init(Cipher.WRAP_MODE, aesKey, mAlgParams);
            
            // even if we have the key export policy configured, RSA private keys
            // are by default unextractable.  we have to manually set that attribute
            // before this operation will succeed
            LunaKey rsaPrivKey = (LunaKey) myPair.getPrivate();
            LunaTokenObject token = LunaTokenObject.LocateObjectByHandle(rsaPrivKey.GetKeyHandle());
            token.SetBooleanAttribute(LunaAPI.CKA_EXTRACTABLE, true);

            wrappedKey = myWrapper.wrap(myPair.getPrivate());

        } catch (InvalidKeyException ikex) {
            // if the key export policy is not configured, the call to wrap() will
            // throw a LunaCryptokiException with error code 0x69, wrapped in an
            // InvalidKeyException as per the JCE spec
            Throwable cause = ikex.getCause();
            if ((cause != null) && (cause instanceof LunaCryptokiException)) {
                LunaCryptokiException lcex = (LunaCryptokiException)cause;
                if (lcex.GetCKRValue() == 0x69) {
                    System.out.println("The private RSA key is not wrappable."
                            + "  Make sure the HSM is configured with the key export capability.");
                    System.exit(1);
                }
            }
            System.out.println("Exception during wrapping of RSA private key");
            ikex.printStackTrace();
            System.exit(1);

        } catch (Exception ex) {
            System.out.println("Exception during wrapping of RSA private key");
            ex.printStackTrace();
            System.exit(1);
        }

        // key is wrapped off so destroy the original
        ((LunaKey) myPair.getPrivate()).DestroyKey();

        // ********************************************
        // unwrap the private key
        // ********************************************
        PrivateKey unwrappedKey = null;
        try {
            Cipher myUnwrapper = Cipher.getInstance("AES/CBC/PKCS5Padding",
            "LunaProvider");
            byte[] ivBytes = { (byte) 65, (byte) 66, (byte) 67, (byte) 68,
                    (byte) 69, (byte) 70, (byte) 71, (byte) 72, (byte) 73,
                    (byte) 74, (byte) 75, (byte) 76, (byte) 77, (byte) 78,
                    (byte) 79, (byte) 80 };
            AlgorithmParameters mAlgParams = AlgorithmParameters.getInstance(
                    "IV", "LunaProvider");
            mAlgParams.init(new IvParameterSpec(ivBytes));

            myUnwrapper.init(Cipher.UNWRAP_MODE, aesKey, mAlgParams);
            unwrappedKey = (LunaPrivateKeyRsa) myUnwrapper.unwrap(wrappedKey,
                    "RSA", Cipher.PRIVATE_KEY);
        } catch (Exception e) {
            System.out.println("Exception attempting to unwrap RSA private key");
            e.printStackTrace();
            System.exit(1);
        }

        // ********************************************
        // decrypt the encrypted value
        // ********************************************
        byte[] decrypted = null;
        try {
            Cipher myCipher = Cipher.getInstance("RSA/NONE/PKCS1v1_5");
            myCipher.init(Cipher.DECRYPT_MODE, unwrappedKey);
            decrypted = myCipher.doFinal(encrypted);
        } catch (Exception e) {
            System.out.println("Exception deciphering the data");
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println("\n\n-----------------------");
        System.out.println("original: " + LunaUtils.getHexString(bytes, true));
        System.out.println("encrypted: " + LunaUtils.getHexString(encrypted, true));
        System.out.println("decrypted: " + LunaUtils.getHexString(decrypted, true));
        System.out.println("\n\n-----------------------");

        if (java.util.Arrays.equals(bytes, decrypted)) {
            System.out.println("Decryption was successful");
        } else {
            System.out.println("*** decryption failed");
        }
        System.out.println("-----------------------\n\n");
    }
}
