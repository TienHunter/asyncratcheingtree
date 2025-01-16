package art.example.groupchat.core;

import java.math.BigInteger;

public class SetupMessage {
    private final int groupId;
    private final String jsonTree;
    private final String jsonMembers;
    private final BigInteger adminIdKey;
    private final BigInteger setupKey;

    public SetupMessage(int groupId, String jsonTree, String jsonMembers, BigInteger adminIdKey, BigInteger setupKey) {
        this.groupId = groupId;
        this.jsonTree = jsonTree;
        this.jsonMembers = jsonMembers;
        this.adminIdKey = adminIdKey;
        this.setupKey = setupKey;
    }

    public int getGroupId() {
        return groupId;
    }

    public String getJsonTree() {
        return jsonTree;
    }

    public String getJsonMembers() {
        return jsonMembers;
    }

    public BigInteger getAdminIdKey() {
        return adminIdKey;
    }

    public BigInteger getSetupKey() {
        return setupKey;
    }
}
