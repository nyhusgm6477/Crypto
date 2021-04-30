import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthOptionPaneUI;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;
import java.util.Scanner;


public class Sender {
    public Socket sendingSock;
    public Socket receivingSock;
    public static final int port = 9045; //idk what the port should be
    public boolean chatFinished = false; //TODO: have gui signal when chat is finished
    public ObjectInputStream dis = null;
    public ObjectOutputStream dos = null;
    public boolean keySent = false;
    private Message msg;
    private Message send;
    private byte[] senderPubKeyEnc = null;
    private byte[] receiverPubKeyEnc = null;
    private byte[] senderSharedSecret = null;
    private SecretKeySpec senderKey;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException {
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

    public void setupSocket() throws IOException, InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeySpecException {
        InetAddress ip = InetAddress.getLocalHost();
        sendingSock = new Socket(ip, port);

        dis = new ObjectInputStream(sendingSock.getInputStream());
        dos = new ObjectOutputStream(sendingSock.getOutputStream());

        DHKeyGen();


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
                    System.out.println("Receiver: " + actualMsg);
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


    public void DHKeyGen() throws NoSuchAlgorithmException, InvalidKeyException, IOException, ClassNotFoundException, InvalidKeySpecException {
        System.out.println("sender generating Diffie-Hellman keypair...\n");
        KeyPairGenerator senderKpairGen = KeyPairGenerator.getInstance("DH");
        senderKpairGen.initialize(2048);
        KeyPair senderKpair = senderKpairGen.generateKeyPair();

        KeyAgreement senderKeyAgree = KeyAgreement.getInstance("DH");
        senderKeyAgree.init(senderKpair.getPrivate());

        senderPubKeyEnc = senderKpair.getPublic().getEncoded();
        System.out.println("public key to send: ");
        for(int i = 0; i < senderPubKeyEnc.length; i++){
            System.out.print(senderPubKeyEnc[i]);
        }

        System.out.println("\n\nAttempting to send public key...");
        dos.writeObject(senderPubKeyEnc);
        System.out.println("Public key successfully sent\n");

        System.out.println("Waiting for key from receiver...");
        receiverPubKeyEnc = (byte[]) dis.readObject();
        System.out.println("Receiver public key received");
        for(int i = 0; i < receiverPubKeyEnc.length; i++){
            System.out.print(receiverPubKeyEnc[i]);
        }

        KeyFactory senderKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec X509KeySpec = new X509EncodedKeySpec(receiverPubKeyEnc);
        PublicKey receiverPubKey = senderKeyFac.generatePublic(X509KeySpec);
        senderKeyAgree.doPhase(receiverPubKey, true);

        try{
            senderSharedSecret = senderKeyAgree.generateSecret();
            int senderLen = senderSharedSecret.length;
            dos.writeObject(senderLen);

            System.out.println("\n\nsender's length: " + senderLen);
        }catch(Exception e){
            System.out.println(e.getMessage());
        }

        System.out.println("\n\nSender's secret: " + toHexString(senderSharedSecret));
        generateKey();
    }

    private static String toHexString(byte[] block) {
        StringBuffer buffer = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            int high = ((block[i] & 0xf0) >> 4);
            int low = (block[i] & 0x0f);
            buffer.append(hex[high]);
            buffer.append(hex[low]);

            if (i < len-1) {
                buffer.append(":");
            }
        }
        return buffer.toString();
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

    public byte[] encryptMessage(String message, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //for AES encryption
        byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message.getBytes()); //check this
        //TODO:pass in key here
        //cipherText.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedMessage = cipherText.doFinal(message.getBytes());

        return encryptedMessage;
    }

    public String decryptMessage(byte[] message, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        String decryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message); //check this
        //decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        //decryptedMessage = decipherText.doFinal(message);
        return decryptedMessage;
    }

    public SecretKeySpec generateKey() throws NoSuchAlgorithmException {
        //SecretKey AES = null;
        //KeyGenerator generator = KeyGenerator.getInstance("AES");
        //generator.init(128);
        //AES = generator.generateKey();
        //return AES;
        return senderKey = new SecretKeySpec(senderSharedSecret, 0, 16, "RSA");
    }
}
