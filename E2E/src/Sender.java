import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;


public class Sender {
    public Socket sendingSock;
    public Socket receivingSock;
    public static final int port = 9045; //idk what the port should be
    public boolean chatFinished = false; //TODO: have gui signal when chat is finished
    public DataInputStream dis = null;
    public DataOutputStream dos = null;

    public static void main(String[] args) {

    }
    public Sender() throws IOException {
        super();
        setupSocket();
    }

    public void setupSocket() throws IOException {
        InetAddress ip = InetAddress.getLocalHost();
        sendingSock = new Socket(ip, port);
        dis = new DataInputStream(sendingSock.getInputStream());
        dos = new DataOutputStream(sendingSock.getOutputStream());
    }

    //method to run chat
    public void chat() throws IOException {
        while(!chatFinished) {
            //constantly listen for messages
            //TODO:probably parse this somehow
            dis.readUTF();
        }
    }

    public void sendMessage(String message) throws IOException {
        //attempt to send the message
        if(!chatFinished) {
            dos.writeUTF(message);
        }
    }

    //a way for the gui to let the socket know to close
    public void setChatFinished(boolean finished) {
        this.chatFinished = finished;
    }
}
