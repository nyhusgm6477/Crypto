import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;


public class Sender {
    public Socket sendingSock;
    public Socket receivingSock;
    public static final int port = 9045; //idk what the port should be
    public boolean chatFinished = false; //TODO: have gui signal when chat is finished
    public ObjectInputStream dis = null;
    public ObjectOutputStream dos = null;
    Message msg;
    Message send;

    public static void main(String[] args) {

    }
    public Sender() throws IOException {
        super();
        Sender snd = new Sender();
        snd.setupSocket();
    }

    public void setupSocket() throws IOException {
        InetAddress ip = InetAddress.getLocalHost();
        sendingSock = new Socket(ip, port);

        dis = new ObjectInputStream(sendingSock.getInputStream());
        dos = new ObjectOutputStream(sendingSock.getOutputStream());

        new receiverSend().start();
        new receiverListener().start();
    }

    class receiverListener extends Thread{
        public void run(){
            while(true){
                try{
                    msg = (Message) dis.readObject();
                    //call decrypt here
                    System.out.println("From receiver: " + msg);
                }catch (Exception e){
                    e.printStackTrace();
                    System.out.println("Error in receiver Listener");
                }
            }
        }
    }

    class receiverSend extends Thread{
        public void run(){
            while(true){
                try{
                    /*
                    *
                    *
                    *
                    * to insert global i with encryption stuff
                    *
                    *
                    * */
                    System.out.println("Message to send to server: ");
                    Scanner sc = new Scanner(System.in);
                    String msg = sc.nextLine();
                    send = new Message(msg.getBytes());
                    dos.writeObject(send);
                }catch (Exception e){
                    e.printStackTrace();
                    System.out.println("No message\n");
                }
            }
        }
    }

    //method to run chat
    public void recieve() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        while(!chatFinished) {
            //constantly listen for messages
            //TODO:probably parse this somehow
            byte[] message  = (byte[]) dis.readObject();
            String decrypted = decryptMessage(message);
        }
    }

    //call only when attempting to send message, like when you hit enter or send or whatever
    public void sendMessage(String message) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //attempt to send the message
        if(!chatFinished) {
            byte[] encrypted = encryptMessage(message);
            dos.write(encrypted);
        }
    }

    //a way for the gui to let the socket know to close
    public void setChatFinished(boolean finished) throws IOException {
        this.chatFinished = finished;
        sendingSock.close();
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
