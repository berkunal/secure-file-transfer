package com.maglor;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Client {
    // TODO: Get port as argument from command line (default 6767)
    static final private int PORT = 6767;

    public static void main(String[] args) {
        Socket clientSocket;

        // TODO: Get url as argument (default localhost)
        String url = "localhost";

        // TODO: Get file path as argument (default smth)
        String filePath = "/Users/ecem/Downloads/testVidoe.mp4";
        try {
            // Connect to server
            System.out.println("Connecting to \u001B[36m" + url + ":" + PORT + "\u001B[0m");
            clientSocket = new Socket(url, PORT);
            System.out.println("Connected");

            // Generate Client's Key Pair
            KeyPair keyPair;
            keyPair = keyPairGenerator();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Receive server's public key
            ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            PublicKey serverPublicKey = (PublicKey) objectInputStream.readObject();

            // Send Client Public Key
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(publicKey);

            // Receive encrypted message which contains randomly generated session key
            DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());
            int len = dataInputStream.readInt();
            byte[] encryptedSessionKey = new byte[len];
            if (len > 0) {
                dataInputStream.readFully(encryptedSessionKey);
            }

            // Decrypt it using client's private key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSessionKey = cipher.doFinal(encryptedSessionKey);
            SecretKey sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");

            // AES cipher
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);

            // File transmission
            ZipOutputStream outputStream = new ZipOutputStream(clientSocket.getOutputStream());
            InputStream inputStream = new FileInputStream(filePath);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, aesCipher);

            File file = new File(filePath);
            long fileSize = file.length();
            System.out.println("Name: " + file.getName() + "\nLength: " + fileSize + " bytes");

            byte[] buffer = new byte[4096];

            ZipEntry zipEntry = new ZipEntry(file.getName());
            outputStream.putNextEntry(zipEntry);

            int count;
            long totalRead = 0;
            while ((count = inputStream.read(buffer)) > 0) {
                totalRead += count;
                cipherOutputStream.write(buffer, 0, count);
                System.out.print("\rSending: " + (totalRead*100/fileSize) + "%");
            }
            System.out.println("\nDone.");

            cipherOutputStream.flush();
            cipherOutputStream.close();
            outputStream.close();
            inputStream.close();
            clientSocket.close();
            System.out.println("Socket closed.");
        } catch (NoSuchAlgorithmException | IOException |InvalidKeyException |NoSuchPaddingException
                |BadPaddingException |IllegalBlockSizeException |InvalidAlgorithmParameterException
                |ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair keyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        return keyPairGenerator.genKeyPair();
    }
}
