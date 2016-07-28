package com.safenetinc.jcprov.sample;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * This class demonstrates using HALogin
 *<p>
 *usage: java ...HALogin -source &lt;sourceID&rt; -target &lt;targetID&rt; -keyName &lt;keyname&rt; [-password &lt;password&rt;]");
 *<li><i>sourceID</i> primary slot ID (source of login key)
 *<li><i>targetID</i> slot to log into
 *<li><i>keyname</i>  label of the login key
 *<li><i>password</i> user password on source slot (omit for PED login)
 */
public class HALogin {

    /** easy access to System.out.println */
    public static void println(String s) {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage() {
        println("");
        println("java ...HALogin -source <sourceID> -target <targetID> -keyName <keyname> [-password <password>]");
        println("");
        println("<sourceID> primary slot ID (source of login key)");
        println("<targetID> slot to log into");
        println("<keyname>  label of the login key");
        println("<password> user password on source slot (omit for PED login)");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args) {
        long sourceSlotId = 1;
        long targetSlotId = 2;
        CK_SESSION_HANDLE sourceSession = new CK_SESSION_HANDLE();
        CK_SESSION_HANDLE targetSession = new CK_SESSION_HANDLE();

        byte[] password = null;
        String keyLabel = "";

        CK_OBJECT_HANDLE sourcePrivateKey;
        CK_SESSION_INFO info = new CK_SESSION_INFO();

        LongRef twcLen = new LongRef();
        LongRef challengeBlobLen = new LongRef();
        LongRef encryptedPinLen = new LongRef();
        LongRef mOfNBlobLen = new LongRef();

        // Setup command line arguments
        for (int i = 0; i < args.length; ++i)
        {
            if(args[i].equalsIgnoreCase("-source"))
            {
                if(++i >= args.length)
                {
                    usage();
                }
                sourceSlotId = Integer.parseInt(args[i]);
            }
            else if(args[i].equalsIgnoreCase("-target"))
            {
                if(++i >= args.length)
                {
                    usage();
                }
                targetSlotId = Integer.parseInt(args[i]);
            }
            else if(args[i].equalsIgnoreCase("-keyName"))
            {
                if(++i >= args.length)
                {
                    usage();
                }
                keyLabel = args[i];
            }
            else if(args[i].equalsIgnoreCase("-password"))
            {
                if(++i >= args.length)
                {
                    usage();
                }
                password = args[i].getBytes();
            }
            else
            {
                usage();
            }
        }

        try 
        {
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            
            // Login to source HSM and get the shared private key
            CryptokiEx.C_OpenSession(sourceSlotId, 
                                     CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION, 
                                     null, 
                                     null,
                                     sourceSession); 
            CryptokiEx.C_Login(sourceSession, CKU.SO, password, (password == null ? 0 : password.length));
            sourcePrivateKey = findObject(sourceSession, keyLabel);

            // Get the Token Wrapping Certificate (TWC) from the source HSM
            CryptokiEx.CA_HAGetMasterPublic(sourceSlotId, null, twcLen);
            byte[] twc = new byte[(int)twcLen.value];
            CryptokiEx.CA_HAGetMasterPublic(sourceSlotId, twc, twcLen);

            // Get the target challenge
            CryptokiEx.C_OpenSession(targetSlotId,
                                     CKF.RW_SESSION | CKF.SERIAL_SESSION | CKF.SO_SESSION,
                                     null,
                                     null,
                                     targetSession); 

            CryptokiEx.CA_HAGetLoginChallenge(targetSession,
                                              CKU.SO,
                                              twc,
                                              twcLen.value,
                                              null,
                                              challengeBlobLen);    
            byte[] challengeBlob = new byte[(int)challengeBlobLen.value];
            CryptokiEx.CA_HAGetLoginChallenge(targetSession,
                                              CKU.SO,
                                              twc,
                                              twcLen.value,
                                              challengeBlob,
                                              challengeBlobLen);    

            // Get the challenge response from the source HSM
            CryptokiEx.CA_HAAnswerLoginChallenge(sourceSession,
                                                 sourcePrivateKey,
                                                 challengeBlob,
                                                 challengeBlobLen.value,
                                                 null,
                                                 encryptedPinLen);
            byte[] encryptedPin = new byte[(int)encryptedPinLen.value];
            CryptokiEx.CA_HAAnswerLoginChallenge(sourceSession,
                                                 sourcePrivateKey,
                                                 challengeBlob,
                                                 challengeBlobLen.value,
                                                 encryptedPin,
                                                 encryptedPinLen);

            // Login to target HSM
            CryptokiEx.CA_HALogin(targetSession,
                                  encryptedPin,
                                  encryptedPinLen.value,
                                  null,
                                  mOfNBlobLen);

            // Session should be logged in as SO state == 4
            CryptokiEx.C_GetSessionInfo(targetSession, info);
            System.out.println("Target session state = " + info.state.longValue());
            
            // Cleanup
            Cryptoki.C_Logout(targetSession);
            Cryptoki.C_CloseSession(targetSession);
            Cryptoki.C_CloseSession(sourceSession);
            
            Cryptoki.C_Finalize(null);

        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        
    }
    
   /** 
    * Locate the first occurence of the specified key
    *
    * @param session
    *  handle to and open session
    *  
    * @param objLabel
    *  label of the key to locate
    */
    static CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE session, String objLabel) {
        byte[] label = objLabel.getBytes();
        LongRef objCount = new LongRef ();
        CK_OBJECT_HANDLE[] hKey = { new CK_OBJECT_HANDLE() };

        CK_ATTRIBUTE[] template = { 
            new CK_ATTRIBUTE(CKA.LABEL, label)
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);
        CryptokiEx.C_FindObjects(session, hKey, hKey.length, objCount);
        CryptokiEx.C_FindObjectsFinal(session);
        if(objCount.value == 1)
        {
            return hKey[0];
        }
        else
        {
            return new CK_OBJECT_HANDLE();
        }
    }
}
