// ****************************************************************************
// Copyright (c) 2010 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * This example illustrates how to use the Luna KeyStore.
 */
public class KeyStoreLunaDemo {

    // Configure these as required.
    private static final int slot = 0;
    private static final String passwd = "userpin";

    public static void main(String[] args) {

        /*
         * The preferred method of logging in to the HSM is through the keystore
         * interface.
         * 
         * We will log in to the first slot
         */
        HSM_Manager.hsmLogin();
        KeyStore myStore = null;

        try {
            ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());

            // The Luna keystore is a Java Cryptography view of the contents
            // of the HSM.
            myStore = KeyStore.getInstance("Luna");

            /*
             * Loading a Luna keystore can be done without specifying an input
             * stream or password if a login was previously done to the first
             * slot.
             * 
             * In this case we have not logged in to the slot and shall do so
             * here.
             * 
             * The byte array input stream contains "slot:1" specifying that we
             * wish to open a keystore corresponding to the slot with ID 1. You
             * can also open keystores by name. using the syntax
             * "tokenlabel:PartitionName"
             */
            myStore.load(is1, passwd.toCharArray());

        } catch (KeyStoreException kse) {
            System.out.println("Unable to create keystore object");
            System.exit(-1);
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Unexpected NoSuchAlgorithmException while loading keystore");
            System.exit(-1);
        } catch (CertificateException e) {
            System.out.println("Unexpected CertificateException while loading keystore");
            System.exit(-1);
        } catch (IOException e) {
            // this should never happen
            System.out.println("Unexpected IOException while loading keystore.");
            System.exit(-1);
        }

        KeyGenerator keyGen = null;
        SecretKey desKey = null;
        try {
            // Generate a DES key
            System.out.println("Generating DES Key");
            // This sample specifies the Luna provider explicitly
            keyGen = KeyGenerator.getInstance("DES", "LunaProvider");
            keyGen.init(56);
            desKey = keyGen.generateKey();
        } catch (Exception e) {
            System.out.println("Exception during Key Generation - " + e.getMessage());
            System.exit(1);
        }

        try {
            // Display information about the Luna Keystore
            System.out.println("Luna Keystore Information");
            System.out.println("Provider - " + myStore.getProvider());
            System.out.println("Type     - " + myStore.getType());
            System.out.println("Size     - " + myStore.size() + " objects");

            // Displaying contents of keystore
            /*
             * The Luna Keystore implementation provides a view of the objects
             * stored in the current Luna HSM.
             */
            System.out.println("Luna Keystore contains");
            Enumeration<String> aliases = myStore.aliases();
            while (aliases.hasMoreElements()) {
                String keyStoreObj = aliases.nextElement();
                System.out.println("\t-" + keyStoreObj);
            }
        } catch (Exception e) {
            System.out.println("Exception accessing Keystore - " + e.getMessage());
            System.exit(1);
        }

        try {
            // Saving DES key to keystore
            /*
             * Even though the DES key created above was created with the Luna
             * Provider (assuming it was the first JCE found), the key is not
             * permanently stored on the Luna HSM automatically. Keys and
             * Certificates are made persistent (or in PKCS#11 terms, become
             * token objects instead of session objects) only when the
             * setKeyEntry() or setCertificateEntry() methods are invoked.
             */
            System.out.println("\nSaving DES to Keystore (This stores the Key on the HSM)");
            myStore.setKeyEntry("DES Demo Key", desKey, null, (java.security.cert.Certificate[]) null);
            System.out.println("Keystore now has " + myStore.size() + " objects");
            System.out.println("Key was made persistant on " + myStore.getCreationDate("DES Demo Key"));
        } catch (Exception e) {
            System.out.println("Exception saving Key to Keystore - " + e.getMessage());
            System.exit(1);
        }

        try {
            // Check to see if the DES key is there
            System.out.println("\nSearching for DES Key in Luna Keystore");
            boolean result = myStore.containsAlias("DES Demo Key");
            if (result == true) {
                System.out.println("Key is present in Keystore\n");
            } else {
                System.out.println("Key is not present in Keystore\n");
            }
        } catch (Exception e) {
            System.out.println("Exception searching for Key - "  + e.getMessage());
        }

        try {
            // Remove the key from the KeyStore
            /*
             * Luna SA partitions have a maximum number of persistent objects
             * they can hold. It is important to clean up old keys and
             * certificates that are no longer used, just like it is necessary
             * to free disk space by erasing unused files.
             * 
             * The LunaSlotManager (TODO: Confirm) class has some special methods to allow you
             * to keep track of the amount of space left on a Luna SA partition.
             */
            System.out.println("Removing DES Key from Keystore");
            myStore.deleteEntry("DES Demo Key");
            HSM_Manager.showObjectCount();

        } catch (Exception e) {
            System.out.println("Exception removing Key - " + e.getMessage());
            System.exit(1);
        }

        HSM_Manager.hsmLogout();
    }
}
