package com.maglor;

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
        String filePath = "/Users/ecem/Downloads/ideaIC-2018.1.1.dmg";
        try {
            // Connect to server
            System.out.println("Connecting to \u001B[36m" + url + ":" + PORT + "\u001B[0m");
            clientSocket = new Socket(url, PORT);
            System.out.println("Connected");

            // Generate Client's Key Pair
            KeyPair keyPair = null;
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
            System.out.println(new String(encryptedSessionKey));

            // Decrypt it using client's private key


            // File transmission
            ZipOutputStream outputStream = new ZipOutputStream(clientSocket.getOutputStream());
            InputStream inputStream = new FileInputStream(filePath);

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
                outputStream.write(buffer, 0, count);
                System.out.print("\rSending: " + (totalRead*100/fileSize) + "%");
            }
            System.out.println("\nDone.");

            outputStream.close();
            inputStream.close();
            clientSocket.close();
            System.out.println("Socket closed.");
        } catch (NoSuchAlgorithmException|ClassNotFoundException|
                IOException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair keyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        return keyPairGenerator.genKeyPair();
    }
}
