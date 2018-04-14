package com.maglor;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ServerHelper extends Thread {
    private Socket socket;
    private String id, plainId;
    private KeyPair keyPair;

    ServerHelper(Socket socket, int id, KeyPair keyPair) {
        this.socket = socket;
        this.id = "\u001B[31mclient_handler_" + id + "\u001B[30m";
        this.plainId = "client_handler_" + id;
        this.keyPair = keyPair;
    }

    public void run() {
        System.out.println(id + ": handles client at " + socket.toString());
        byte[] buffer = new byte[4096];

        // Servers private and public keys
        PublicKey publicKey = keyPair.getPublic();
        //PrivateKey privateKey = keyPair.getPrivate();

        try {
            // Send server's public key to client
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(publicKey);

            // Get Client Public Key
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            PublicKey clientPublicKey = (PublicKey) objectInputStream.readObject();

            // Generate session key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();

            // Encrypt it with clients public key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            byte[] encryptedSessionKey = cipher.doFinal(sessionKey.getEncoded());

            // Send encrypted session key
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            int len = encryptedSessionKey.length;
            dos.writeInt(len);
            if (len > 0) {
                dos.write(encryptedSessionKey, 0, len);
            }

            // AES cipher
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParameterSpec);

            // Stream coming to server (encrypted and in compressed form)
            ZipInputStream inputStream = new ZipInputStream(socket.getInputStream());
            CipherInputStream cipherInputStream = new CipherInputStream(inputStream, aesCipher);

            ZipEntry entry;
            String entryName;
            while((entry = inputStream.getNextEntry())!=null)
            {
                entryName = entry.getName();
                System.out.println(id + ": Receiving " + entryName + " from " + socket.toString());
                OutputStream outputStream = new FileOutputStream(plainId + "_" + entryName);

                int count;
                while ((count = cipherInputStream.read(buffer)) > 0) {
                    outputStream.write(buffer, 0, count);
                }

                System.out.println(id + ": " + entryName + " received successfully from " + socket.toString());

                cipherInputStream.close();
                outputStream.close();
            }

            inputStream.close();
        } catch (IOException |ClassNotFoundException
                |NoSuchAlgorithmException |NoSuchPaddingException
                |InvalidKeyException |BadPaddingException |IllegalBlockSizeException |InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
