import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Receiver extends JFrame implements ActionListener, KeyListener {

    private static ServerSocket server =  null;
    private static Socket clientSocket = null;
    private static String ip = "127.0.0.1";
    private static int port = 9045;
    public boolean chatFinished = false;
    private byte[] msg;
    Message send;
    private byte[] senderPubKeyEnc = null;
    private byte[] receiverPubKeyEnc = null;
    byte[] receiverSharedSecret;
    public boolean eventsLog = false;
    SecretKeySpec receiverKey;
    AlgorithmParameters aesParameters;
    private JButton sendbutton;
    private JTextArea chat, event;
    private JTextField typefield;
    private JButton EventLogButton;


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
            System.out.println("Server running\n");
            event.append("\nServer running\n");
            clientSocket = server.accept();
            System.out.println("Accepted client\n");
            event.append("\nAccepted client\n");
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
                    recvIV();
                    msg = (byte[]) is.readObject();
                    event.append("\n\nEncrypted message from Sender(Hex): \n" + toHexString(msg));
                    event.append("\n\nEncrypted message from Sender(Base64): \n" + Base64.getEncoder().encodeToString(msg));
                    byte[] output = decryptMessage(msg);
                    String actualMsg = new String(output, StandardCharsets.UTF_8);
                    System.out.println("From Sender: " + actualMsg);
                    chat.append("\nFrom Sender: " + actualMsg);

                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    class clientSend extends Thread{
        public void run(){
            while(true){
                try{
                    System.out.println("Me(Receiver): ");
                    Scanner sc = new Scanner(System.in);
                    String msg = sc.nextLine();
                    sendMessage(msg);
                    chat.append("\nMe(Receiver): " + msg);

                }catch(Exception e){
                    e.printStackTrace();

                }
            }
        }

    }

    public void DHKeyGen() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ClassNotFoundException {
        System.out.println("Waiting for Sender's public key...");
        event.append("\nWaiting for Sender's public key...\n");
        senderPubKeyEnc = (byte[]) is.readObject();
        System.out.println("Public key from Sender received \n");
        event.append("\nPublic key from Sender received \n");

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
        System.out.println("\nAttempting to send Receiver's public key to Sender...\n");
        event.append("\nAttempting to send Receiver's public key to Sender...\n");
        String publickeytemp;
        for(int i = 0; i < receiverPubKeyEnc.length; i++){
            System.out.print(receiverPubKeyEnc[i]);
            event.append(""+receiverPubKeyEnc[i]);
        }
        os.writeObject(receiverPubKeyEnc);
        System.out.println("\nReceiver's public key sent");
        event.append("\nReceiver's public key sent");

        receiverKeyAgree.doPhase(senderPubKey, true);

        int senderLen = (int)is.readObject();
        System.out.println("\n\nSender's public key length: \n" + senderLen);
        event.append("\n\nSender's public key length: \n" + senderLen);
        try {
            receiverSharedSecret = new byte[senderLen];
            int receiverLen = receiverKeyAgree.generateSecret(receiverSharedSecret, 0);
        } catch(ShortBufferException e){
            System.out.println(e.getMessage());
        }

        System.out.println("\n\nReceiver's secret(Hex): \n" + toHexString(receiverSharedSecret));
        event.append("\n\nReceiver's secret(Hex): \n" + toHexString(receiverSharedSecret));
        System.out.println("\n\nReceiver's secret(Base64): \n" + Base64.getEncoder().encodeToString(receiverSharedSecret));
        event.append("\n\nReceiver's secret(Base64): \n" + Base64.getEncoder().encodeToString(receiverSharedSecret));


        generateAESKey();
        System.out.println("\n\nGenerated key(Hex): \n" + toHexString(receiverKey.getEncoded()));
        event.append("\n\nGenerated key(Hex): \n" + toHexString(receiverKey.getEncoded()));
        System.out.println("\n\nGenerated key(Base64): \n" + Base64.getEncoder().encodeToString(receiverKey.getEncoded()));
        event.append("\n\nGenerated key(Base64): \n" + Base64.getEncoder().encodeToString(receiverKey.getEncoded()));

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

    /*
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
     */

    //call only when attempting to send message, like when you hit enter or send or whatever
    public void sendMessage(String message) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //attempt to send the message
        if(!chatFinished) {
            byte[] encrypted = encryptMessage(message);
            event.append("\n\nEncrypted message to send (Hex): \n" + toHexString(encrypted));
            event.append("\n\nEncrypted message to send (Base64): \n" + Base64.getEncoder().encodeToString(encrypted));
            os.writeObject(encrypted);
        }
    }

    public byte[] encryptMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, IOException {

       /* byte[] encryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message.getBytes()); //check this
        //TODO:pass in key here
        //cipherText.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedMessage = cipherText.doFinal(message.getBytes());
        if(eventsLog) {
            String encryptedText = "Encrypted text: " + Base64.getEncoder().encodeToString(encryptedMessage);
        }
        */
        //return encryptedMessage;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //for AES encryption
        cipher.init(Cipher.ENCRYPT_MODE, receiverKey);
        byte[] cipherText = cipher.doFinal(message.getBytes());
        byte[] encodedParameters = cipher.getParameters().getEncoded();
        os.writeObject(encodedParameters);
        return cipherText;
    }

    public void recieve() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //while(!chatFinished) {
            //constantly listen for messages
            byte[] message  = (byte[]) is.readObject();
            //String decrypted = decryptMessage(message, key);
        //}
    }

    public byte[] decryptMessage(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        decipherText.init(Cipher.DECRYPT_MODE, receiverKey, aesParameters);
        byte[] decryptedMessage = decipherText.doFinal(message);
        //IvParameterSpec iv = new IvParameterSpec(message); //check this
        //TODO:pass in key here
        //decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        //decryptedMessage = decipherText.doFinal(message);
        return decryptedMessage;
    }

    public void recvIV() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        byte[] encodedParameters = (byte[]) is.readObject();
        aesParameters = AlgorithmParameters.getInstance("AES");
        aesParameters.init(encodedParameters);
    }

    public void generateAESKey() throws NoSuchAlgorithmException {
        /*
        SecretKey AES;
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        AES = generator.generateKey();
        if(eventsLog) {
            String AESText = "Generated key: " + Base64.getEncoder().encodeToString(AES.getEncoded()); //getting string version of key
        }
         */
        receiverKey = new SecretKeySpec(receiverSharedSecret, 0, 16, "AES");


    }

    Receiver()
    {
        JPanel center = new JPanel(new GridLayout(2,1));
        chat = new JTextArea(80,80);
        chat.setEditable(false);
        appendRoom("Chat Log:\n");
        center.add(new JScrollPane(chat));
        event = new JTextArea(80,80);
        event.setEditable(false);
        appendEvent("Events log.\n");
        center.add(new JScrollPane(event));
        add(center);

        JPanel south = new JPanel( new BorderLayout());
        typefield = new JTextField("Type here",33);

        south.add(typefield,BorderLayout.NORTH);

        JPanel ButtonPanel = new JPanel();
        EventLogButton = new JButton("Event Log");
        sendbutton = new JButton("Send");

        ButtonPanel.add(EventLogButton,BorderLayout.SOUTH);
        ButtonPanel.add(sendbutton,BorderLayout.SOUTH);
        south.add(ButtonPanel, BorderLayout.SOUTH);

        add(south, BorderLayout.SOUTH);

        setTitle("Receiver");
        setSize(400, 600);
        setVisible(true);


        sendbutton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!typefield.getText().equals(""))
                {
                    try{

                        String msg = typefield.getText();
                        sendMessage(msg);
                        typefield.setText("");
                        chat.append("\nMe(Receiver): " + msg);
                        System.out.println("Me(Receiver): " + msg);

                    }catch(Exception a){
                        a.printStackTrace();
                        System.out.println("Message not sent");
                        event.append("Message not sent");
                    }
                }
            }

        });

        EventLogButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                if(event.isVisible())
                {
                    event.setVisible(false);
                }
                else
                {
                    event.setVisible(true);
                }
            }
        });

        typefield.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!typefield.getText().equals(""))
                {
                    try{

                        String msg = typefield.getText();
                        sendMessage(msg);
                        typefield.setText("");
                        chat.append("\nMe(Receiver): " + msg);
                        System.out.println("Me(Receiver): " + msg);
                    }catch(Exception a){
                        a.printStackTrace();
                        System.out.println("Message not sent");
                        event.append("Message not sent");
                    }
                }

            }
        });
    }

    void appendRoom(String str)
    {
        chat.append(str);
        chat.setCaretPosition(chat.getText().length() - 1);
    }
    void appendEvent(String str)
    {
        event.append(str);
        event.setCaretPosition(chat.getText().length() - 1);
    }


    @Override
    public void actionPerformed(ActionEvent e) {
        Component Receiver = new JFrame();

    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {
    }

    @Override
    public void keyReleased(KeyEvent arg0) {

    }

}

//Push Test