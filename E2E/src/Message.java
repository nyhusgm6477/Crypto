import java.io.Serializable;

public class Message implements Serializable {
    byte[] data;
    Message(byte[] data){
        this.data = data;
    }

    byte[] retrieveData(){
        return data;
    }
}
