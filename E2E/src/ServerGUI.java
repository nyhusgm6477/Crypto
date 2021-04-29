import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class ServerGUI extends JFrame
{

    private JButton stopStart;
    private JButton send;
    private JTextArea chat, event;

    ServerGUI()
    {
        super("Receiver");

        JPanel north = new JPanel();

        stopStart = new JButton("Start");
        send = new JButton("Send");
        north.add(stopStart);
        north.add(send);
        add(north, BorderLayout.NORTH);

        JPanel center = new JPanel(new GridLayout(2,1));
        chat = new JTextArea(80,80);
        chat.setEditable(false);
        appendRoom("Chat room.\n");
        center.add(new JScrollPane(chat));
        event = new JTextArea(80,80);
        event.setEditable(false);
        appendEvent("Events log.\n");
        center.add(new JScrollPane(event));
        add(center);

        setSize(400, 600);
        setVisible(true);
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

    public static void main(String[] arg)
    {
        new ServerGUI();
    }
}

