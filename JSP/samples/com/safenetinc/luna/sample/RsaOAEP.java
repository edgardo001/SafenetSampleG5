// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.param.LunaParameterSpecOAEP;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.PSource.PSpecified;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * This sample demonstrates RSA OAEP encryption
 */
public class RsaOAEP {

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
            // need to make an rsa keypair
            // ********************************************
            kpg = KeyPairGenerator.getInstance("RSA", "LunaProvider");
            kpg.initialize(1024);
            myPair = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Exception generating keypair");
            e.printStackTrace();
        }

        byte[] input = "abc".getBytes();
        byte[] param = "abcd".getBytes();
        PSource paramSource = new PSpecified(param);
        PSource badParams = new PSpecified("dcba".getBytes());
        Cipher cipher = null;
        Key pubKey = null;
        Key privKey = null;
        byte[] cipherText = null;

        try {
            cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding",
                    "LunaProvider");

            pubKey = myPair.getPublic();
            privKey = myPair.getPrivate();

            // make oaep parameter spec
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-1", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA1, paramSource); // OAEPParameterSpec.DEFAULT;
            // default should be good for us.

            // make a luna one
            LunaParameterSpecOAEP lunaSpec = new LunaParameterSpecOAEP();

            cipher.init(Cipher.ENCRYPT_MODE, pubKey, oaepSpec);
            cipherText = cipher.doFinal(input);
            System.out.println("cipherText: "
                    + LunaUtils.getHexString(cipherText, true));

            cipher.init(Cipher.ENCRYPT_MODE, pubKey, lunaSpec);
            byte[] lunaBytes = cipher.doFinal(input);
            System.out.println("luna cipher Text: "
                    + LunaUtils.getHexString(lunaBytes, true));

            // decrypt
            cipher.init(Cipher.DECRYPT_MODE, privKey, oaepSpec);
            byte[] decryptedText = cipher.doFinal(cipherText);

            cipher.init(Cipher.DECRYPT_MODE, privKey, lunaSpec);
            byte[] lunaDecrypted = cipher.doFinal(lunaBytes);

            // display original and decrypted
            System.out.println("  Original: " + LunaUtils.getHexString(input, true));
            System.out.println("  decrypted: "
                    + LunaUtils.getHexString(decryptedText, true));
            System.out.println("  decrypted (luna spec): "
                    + LunaUtils.getHexString(lunaDecrypted, true));

        } catch (Exception e) {
            System.out.println("*** Unexpected Exception ***");
            e.printStackTrace();
        }

        // try a bad param spec
        try {
            OAEPParameterSpec badSpec = new OAEPParameterSpec("SHA-1", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA1, badParams);
            cipher.init(Cipher.DECRYPT_MODE, privKey, badSpec);
            byte[] invalidText = cipher.doFinal(cipherText);
            System.out.println("  bad spec: "
                    + LunaUtils.getHexString(invalidText, true));

        } catch (IllegalBlockSizeException ex) {
            // the LunaCryptokiException from the JNI layer is wrapped in an IllegalBlockSizeException
            // to be more compatible with the JCE spec
            if (ex.getMessage().contains("function 'C_Decrypt' returns 0x5")) {
                System.out.println("Got expected exception from an invalid P source used during decryption.");
            } else {
                System.out.println("*** Unexpected Exception ***");
                ex.printStackTrace();          
            }
        } catch (Exception e) {
            System.out.println("*** Unexpected Exception ***");
            e.printStackTrace();
        }
    }
}
