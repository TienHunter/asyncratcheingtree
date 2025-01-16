package art.example.groupchat.core;

public class Message {
    private final String from;
    private final int groupId;
    private final String updatePath;
    private final String cipherText;

    public Message(String from, int groupId, String updatePath, String cipherText) {
        this.from = from;
        this.groupId = groupId;
        this.updatePath = updatePath;
        this.cipherText = cipherText;
    }

    public String getFrom() {
        return from;
    }

    public int getGroupId() {
        return groupId;
    }

    public String getUpdatePath() {
        return updatePath;
    }

    public String getCipherText() {
        return cipherText;
    }
}
