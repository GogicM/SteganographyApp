/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

/**
 *
 * @author Milan
 */
public class Server {
    private static final int PORT = 9999;
    
    
    public static void main(String[] args) {
        try {
            ServerSocket sSocket = new ServerSocket(PORT);
            while(true) {
                Socket s = sSocket.accept();
                new ServerThread(s);
                            System.out.println("Client connected");

            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
    
}
