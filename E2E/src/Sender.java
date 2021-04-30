import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;


public class Sender {
    public Socket sendingSock;
    public Socket receivingSock;
    public static final int port = 9045; //idk what the port should be
    public boolean chatFinished = false; //TODO: have gui signal when chat is finished
    public boolean isVerbose = false; //TODO: set this to true if we want to show encryption/keys
    public ObjectInputStream dis = null;
    public ObjectOutputStream dos = null;
    Message msg;
    Message send;

    public static void main(String[] args) throws IOException {
        Sender s = null;
        try {
            s = new Sender();
        } catch (IOException e) {
            e.printStackTrace();
        }
        s.setupSocket();
    }
    public Sender() throws IOException {
        //super();
       // Sender snd = new Sender();
       // snd.setupSocket();
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
                    String actualMsg = new String(msg.retrieveData(), StandardCharsets.UTF_8);
                    System.out.println("From receiver: " + actualMsg);
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
            byte[] message  = (byte[]) dis.readObject();
            //String decrypted = decryptMessage(message, key);
        }
    }

    //call only when attempting to send message, like when you hit enter or send or whatever
    public void sendMessage(String message) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //attempt to send the message
        if(!chatFinished) {
            //byte[] encrypted = encryptMessage(message, key);
            //dos.write(encrypted);
        }
    }

    //a way for the gui to let the socket know to close
    public void setChatFinished(boolean finished) throws IOException {
        this.chatFinished = finished;
        sendingSock.close();
    }

    public byte[] encryptMessage(String message, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //for AES encryption
        byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message.getBytes()); //check this
        cipherText.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedMessage = cipherText.doFinal(message.getBytes());
        if(isVerbose) {
            String encryptedText = "Encrypted text: " + Base64.getEncoder().encodeToString(encryptedMessage);
        }
        return encryptedMessage;
    }

    public String decryptMessage(byte[] message, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        String decryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message); //check this
        decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        decryptedMessage = decipherText.doFinal(message).toString(); //this kinda sus
        return decryptedMessage;
    }

    public SecretKey generateKey() throws NoSuchAlgorithmException {
        SecretKey AES = null;
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        AES = generator.generateKey();
        if(isVerbose) {
            String AESText = "Generated key: " + Base64.getEncoder().encodeToString(AES.getEncoded()); //getting string version of key
        }
        return AES;
    }
}
