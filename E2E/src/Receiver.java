import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;


public class Receiver {

    private static ServerSocket server =  null;
    private static Socket clientSocket = null;
    private static String ip = "127.0.0.1";
    private static int port = 9045;
    private Message msg;
    Message send;

    int i;

    ObjectOutputStream os = null;
    ObjectInputStream is = null;


    public static void main(String[] args) throws IOException {
        Receiver rcv = new Receiver();
        rcv.setupServer();
    }

    public void setupServer() {
        try{
            server = new ServerSocket(port);
            System.out.println("server running\n");
            clientSocket = server.accept();
            System.out.println("accepted client\n");
            senderThread thread = new senderThread(clientSocket);
            thread.run();
            server.close();
        } catch (IOException u){
            System.out.println(u);
        }
    }

    class senderThread extends Thread{
        Socket socket;
        senderThread(Socket socket) throws IOException{
            this.socket = socket;
            os = new ObjectOutputStream(socket.getOutputStream());
            is = new ObjectInputStream(socket.getInputStream());
            new clientListener().start();
            new clientSend().start();
        }
    }

    class clientListener extends Thread{
        public void run(){
            while(true){
                try{
                    msg = (Message)is.readObject();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
                System.out.println("Message from client: " + msg);
            /*
                if(i == 0){
                    if(msg.retrieveData() != null){
                        try {
                            decryptMessage(msg.retrieveData());
                        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException e) {
                            e.printStackTrace();
                        }
                    }
                    else{
                        System.out.println("SOME PROBLEM\n");
                    }
                }
            */
            }
        }
    }

    class clientSend extends Thread{
            public void run(){
                while(true){
                    try{
                        System.out.println("To send: ");
                        Scanner sc = new Scanner(System.in);
                        String msg = sc.nextLine();
                        send = new Message(msg.getBytes());

                        synchronized (send){
                            os.writeObject(send);
                            os.reset();
                        }

                    }catch(Exception e){
                        e.printStackTrace();
                        System.out.println("Message not sent");
                    }
                }
            }

    }

    public byte[] encryptMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //for AES encryption
        byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message.getBytes()); //check this
        //TODO:pass in key here
        //cipherText.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedMessage = cipherText.doFinal(message.getBytes());

        return encryptedMessage;
    }


    public String decryptMessage(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        String decryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message); //check this
        //TODO:pass in key here
        //decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        //decryptedMessage = decipherText.doFinal(message);
        return decryptedMessage;
    }

}
