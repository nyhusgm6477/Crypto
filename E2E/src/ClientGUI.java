import javax.swing.*;
import java.awt.*;

public class ClientGUI extends JFrame
{

    private static final long serialVersionUID = 1L;
    private JButton send;
    private JTextArea ta;

    ClientGUI()
    {
        super("Sender");
        JPanel northPanel = new JPanel(new GridLayout(3,1));
        add(northPanel, BorderLayout.NORTH);

        ta = new JTextArea("Welcome to the Chat room\n", 80, 80);
        JPanel centerPanel = new JPanel(new GridLayout(1,1));
        centerPanel.add(new JScrollPane(ta));
        ta.setEditable(false);
        add(centerPanel, BorderLayout.CENTER);

        send = new JButton("Send");

        JPanel southPanel = new JPanel();
        southPanel.add(send);
        add(southPanel, BorderLayout.SOUTH);

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(600, 600);
        setVisible(true);
    }

    public static void main(String[] args)
    {
        new ClientGUI();
    }

}

