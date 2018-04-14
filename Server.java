package com.maglor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

public class Server {
    // TODO: Get port as argument from command line (default 6767)
    static final int PORT = 6767;

    public static void main(String argv[]) {
        // Generate Server's Key Pair
        KeyPair keyPair = null;
        try {
            keyPair = keyPairGenerator();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Initialize TCP socket
        int serverHelperID = 0;
        ServerSocket serverSocket = null;
        Socket socket = null;
        try {
            serverSocket = new ServerSocket(PORT);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Server Socket is listening at port \u001B[36m" + PORT + "\u001B[30m");

        while (true) {
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                e.printStackTrace();
            }

            new ServerHelper(socket, serverHelperID, keyPair).start();
            serverHelperID++;
        }
    }

    private static KeyPair keyPairGenerator() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.genKeyPair();
    }
}
