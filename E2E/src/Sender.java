import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.plaf.synth.SynthOptionPaneUI;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;
import java.util.Base64;
import java.util.Scanner;


public class Sender extends JFrame implements ActionListener, KeyListener {
    public Socket sendingSock;
    public Socket receivingSock;
    public static final int port = 9045; //idk what the port should be
    public boolean chatFinished = false; //TODO: have gui signal when chat is finished
    public ObjectInputStream dis = null;
    public ObjectOutputStream dos = null;
    public boolean keySent = false;
    public boolean eventsLog = false;
    private byte[] msg;
    private Message send;
    private byte[] senderPubKeyEnc = null;
    private byte[] receiverPubKeyEnc = null;
    private byte[] senderSharedSecret = null;
    private SecretKeySpec senderKey;
    AlgorithmParameters aesParameters;
    private JButton sendbutton;
    private JTextArea chat, event;
    private JTextField typefield;
    private JButton EventLogButton;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException {
        Sender s = null;
        s = new Sender();
        s.setupSocket();
    }


    public void setupSocket() throws IOException, InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeySpecException {
        InetAddress ip = InetAddress.getLocalHost();
        sendingSock = new Socket(ip, port);

        dis = new ObjectInputStream(sendingSock.getInputStream());
        dos = new ObjectOutputStream(sendingSock.getOutputStream());

        event.append("\nConnected to Receiver\n");

        DHKeyGen();


        new receiverSend().start();
        new receiverListener().start();
    }

    class receiverListener extends Thread{
        public void run(){
            while(true){
                try{
                    recvIV();
                    msg = (byte[]) dis.readObject();
                    event.append("\n\nEncrypted message from Receiver(Hex): \n" + toHexString(msg));
                    event.append("\n\nEncrypted message from Receiver(Base64): \n" + Base64.getEncoder().encodeToString(msg));
                    byte[] output = decryptMessage(msg);
                    String actualMsg = new String(output, StandardCharsets.UTF_8);
                    System.out.println("Receiver: " + actualMsg);
                    chat.append("\nReceiver: " + actualMsg);
                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
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
                    System.out.println("Me(Sender): ");
                    Scanner sc = new Scanner(System.in);
                    String msg = sc.nextLine();
                    sendMessage(msg);
                    chat.append("\nMe(Sender): " + msg);
                }catch (Exception e){
                    e.printStackTrace();
                    System.out.println("No message\n");
                    event.append("\nNo message\n");
                }
            }
        }
    }


    public void DHKeyGen() throws NoSuchAlgorithmException, InvalidKeyException, IOException, ClassNotFoundException, InvalidKeySpecException {
        System.out.println("\nSender generating Diffie-Hellman keypair...\n");
        event.append("\nSender generating Diffie-Hellman keypair...\n");
        KeyPairGenerator senderKpairGen = KeyPairGenerator.getInstance("DH");
        senderKpairGen.initialize(2048);
        KeyPair senderKpair = senderKpairGen.generateKeyPair();

        KeyAgreement senderKeyAgree = KeyAgreement.getInstance("DH");
        senderKeyAgree.init(senderKpair.getPrivate());

        senderPubKeyEnc = senderKpair.getPublic().getEncoded();
        System.out.println("Attempting to send Sender's public key to Receiver... \n");
        event.append("\nAttempting to send Sender's public key to Receiver... \n");
        for(int i = 0; i < senderPubKeyEnc.length; i++){
            System.out.print(senderPubKeyEnc[i]);
            event.append(""+senderPubKeyEnc[i]);
        }
        dos.writeObject(senderPubKeyEnc);
        System.out.print("\nSender's public key sent\n");
        event.append("\nSender's public key sent\n");

        System.out.println("Waiting for key from receiver...\n");
        event.append("\nWaiting for key from receiver...\n");
        receiverPubKeyEnc = (byte[]) dis.readObject();
        System.out.println("Receiver public key received: \n");
        event.append("\nReceiver public key received: \n");
        for(int i = 0; i < receiverPubKeyEnc.length; i++){
            System.out.print(receiverPubKeyEnc[i]);
            event.append(""+receiverPubKeyEnc[i]);
        }

        KeyFactory senderKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec X509KeySpec = new X509EncodedKeySpec(receiverPubKeyEnc);
        PublicKey receiverPubKey = senderKeyFac.generatePublic(X509KeySpec);
        senderKeyAgree.doPhase(receiverPubKey, true);

        try{
            senderSharedSecret = senderKeyAgree.generateSecret();
            int senderLen = senderSharedSecret.length;
            dos.writeObject(senderLen);

            System.out.println("\n\nSender's public key length: \n" + senderLen);
            event.append("\n\nSender's public key length: \n" + senderLen);
        }catch(Exception e){
            System.out.println(e.getMessage());
        }

        System.out.println("\n\nSender's secret(Hex): \n" + toHexString(senderSharedSecret));
        event.append("\n\nSender's secret(Hex): \n" + toHexString(senderSharedSecret));
        System.out.println("\n\nSender's secret(Base64): \n" + Base64.getEncoder().encodeToString(senderSharedSecret));
        event.append("\n\nSender's secret(Base64): \n" + Base64.getEncoder().encodeToString(senderSharedSecret));
        generateAESKey();
        System.out.println("\n\nGenerated key(Hex): \n" + toHexString(senderKey.getEncoded()));
        event.append("\n\nGenerated key(Hex): \n" + toHexString(senderKey.getEncoded()));
        System.out.println("\n\nGenerated key(Base64): \n" + Base64.getEncoder().encodeToString(senderKey.getEncoded()));
        event.append("\n\nGenerated key(Base64): \n" + Base64.getEncoder().encodeToString(senderKey.getEncoded()));


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
    public void sendMessage(String message) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //attempt to send the message
        if(!chatFinished) {
            byte[] encrypted = encryptMessage(message);
            event.append("\n\nEncrypted message to send to Receiver(Hex): \n" + toHexString(encrypted));
            event.append("\n\nEncrypted message to send to Receiver(Base64): \n" + Base64.getEncoder().encodeToString(encrypted));
            dos.writeObject(encrypted);
        }
    }

    //a way for the gui to let the socket know to close
    public void setChatFinished(boolean finished) throws IOException {
        this.chatFinished = finished;
        sendingSock.close();
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
        cipher.init(Cipher.ENCRYPT_MODE, senderKey);
        byte[] cipherText = cipher.doFinal(message.getBytes());
        byte[] encodedParameters = cipher.getParameters().getEncoded();
        dos.writeObject(encodedParameters);
        return cipherText;
    }

    public byte[] decryptMessage(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        decipherText.init(Cipher.DECRYPT_MODE, senderKey, aesParameters);
        byte[] decryptedMessage = decipherText.doFinal(message);
        //IvParameterSpec iv = new IvParameterSpec(message); //check this
        //TODO:pass in key here
        //decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        //decryptedMessage = decipherText.doFinal(message);
        return decryptedMessage;
    }

    /*
    public String decryptMessage(byte[] message, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher decipherText = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        String decryptedMessage = null;
        IvParameterSpec iv = new IvParameterSpec(message); //check this
        //decipherText.init(Cipher.DECRYPT_MODE, key, iv);
        //decryptedMessage = decipherText.doFinal(message);
        return decryptedMessage;
    }
     */

    public void generateAESKey() throws NoSuchAlgorithmException {
        /*
        SecretKey AES;
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        AES = generator.generateKey();
        if(eventsLog) {
            String AESText = "Generated key: " + Base64.getEncoder().encodeToString(AES.getEncoded()); //getting string version of key
        }
        return AES;

         */
        senderKey = new SecretKeySpec(senderSharedSecret, 0, 16, "AES");
    }

    public void recvIV() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        byte[] encodedParameters = (byte[]) dis.readObject();
        aesParameters = AlgorithmParameters.getInstance("AES");
        aesParameters.init(encodedParameters);
    }



    Sender()
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

        setTitle("Sender");
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
                        chat.append("\nMe(Sender): " + msg);
                        System.out.println("Me(Sender): " + msg);

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
                        chat.append("\nMe(Sender): " + msg);
                        System.out.println("Me(Sender): " + msg);
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
