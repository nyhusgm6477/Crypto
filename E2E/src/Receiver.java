import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Receiver {

    private static ServerSocket server =  null;
    private static Socket clientSocket = null;
    private static String ip = "127.0.0.1";
    private static int port = 9045;
    private Message msg;
    Message send;
    private byte[] senderPubKeyEnc = null;
    private byte[] receiverPubKeyEnc = null;
    byte[] receiverSharedSecret;
    public boolean eventsLog = false;

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
        } catch (IOException | ClassNotFoundException | InvalidKeySpecException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeyException u){
            System.out.println(u);
        }
    }

    class senderThread extends Thread{
        Socket socket;
        senderThread(Socket socket) throws IOException, ClassNotFoundException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException {
            this.socket = socket;
            os = new ObjectOutputStream(socket.getOutputStream());
            is = new ObjectInputStream(socket.getInputStream());

            DHKeyGen();

            new clientListener().start();
            new clientSend().start();
        }
    }

    class clientListener extends Thread{
        public void run(){
            while(true){
                try{
                    msg = (Message)is.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
                String actualMsg = new String(msg.retrieveData(), StandardCharsets.UTF_8);
                System.out.println("Sender: " + actualMsg);
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

    public void DHKeyGen() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ClassNotFoundException {
        System.out.println("Waiting for sender's public key...");
        senderPubKeyEnc = (byte[]) is.readObject();
        System.out.println("Public key from sender received: ");

        for(int i = 0; i < senderPubKeyEnc.length; i++){
            System.out.print(senderPubKeyEnc[i]);
        }

        /*instantiating DH public key from encoded sender key*/
        KeyFactory receiverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec X509KeySpec = new X509EncodedKeySpec(senderPubKeyEnc);

        PublicKey senderPubKey = receiverKeyFac.generatePublic(X509KeySpec);
        DHParameterSpec dhParamFromSenderPubKey = ((DHPublicKey)senderPubKey).getParams();

        /*creating receiver's own public key*/
        KeyPairGenerator receiverKpairGen = KeyPairGenerator.getInstance("DH");
        receiverKpairGen.initialize(dhParamFromSenderPubKey);
        KeyPair receiverKpair = receiverKpairGen.generateKeyPair();

        KeyAgreement receiverKeyAgree = KeyAgreement.getInstance("DH");
        receiverKeyAgree.init(receiverKpair.getPrivate());

        receiverPubKeyEnc = receiverKpair.getPublic().getEncoded();
        System.out.println("\n\nAttempting to send receiver's public key to sender...");
        for(int i = 0; i < receiverPubKeyEnc.length; i++){
            System.out.print(receiverPubKeyEnc[i]);
        }
        os.writeObject(receiverPubKeyEnc);
        System.out.println("\nReceiver's public key sent");

        receiverKeyAgree.doPhase(senderPubKey, true);

        int senderLen = (int)is.readObject();
        System.out.println("\n\nsenderlen: " + senderLen);
        try {
            receiverSharedSecret = new byte[senderLen];
            int receiverLen = receiverKeyAgree.generateSecret(receiverSharedSecret, 0);
        } catch(ShortBufferException e){
            System.out.println(e.getMessage());
        }

        System.out.println("\n\nReceiver's secret: " + toHexString(receiverSharedSecret));
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


    public byte[] encryptMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //for AES encryption
        byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message.getBytes()); //check this
        //TODO:pass in key here
        //cipherText.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedMessage = cipherText.doFinal(message.getBytes());
        if(eventsLog) {
            String encryptedText = "Encrypted text: " + Base64.getEncoder().encodeToString(encryptedMessage);
        }
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

    public SecretKey generateAESKey() throws NoSuchAlgorithmException {
        SecretKey AES;
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        AES = generator.generateKey();
        if(eventsLog) {
            String AESText = "Generated key: " + Base64.getEncoder().encodeToString(AES.getEncoded()); //getting string version of key
        }
        return AES;
    }
}
