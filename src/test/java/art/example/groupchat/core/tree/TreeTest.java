package art.example.groupchat.core.tree;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import art.example.groupchat.core.crypto.CryptoUtils;
import art.example.groupchat.core.crypto.X25519Utils;
import art.example.groupchat.core.crypto.XECKeyPair;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static art.example.groupchat.core.serialize.SerializeUtils.*;

class TreeTest {

    String member = "member-3";
    List<LeafNode> leaves;
    XECKeyPair adminIdKey;
    XECKeyPair setupKey;
    Map<String, XECKeyPair> memberIdKeys = new HashMap<>();
    Map<String, XECKeyPair> memberEphemeralKeys = new HashMap<>();

    @BeforeEach
    void setUp() {
        adminIdKey = X25519Utils.newKeyPair();
        setupKey = X25519Utils.newKeyPair();
        List<String> usernames = new ArrayList<>();
        Map<String, XECPublicKey> theirIdKeys = new HashMap<>();
        Map<String, XECPublicKey> theirEphemeralKeys = new HashMap<>();
        for (int i = 0; i < 6; i++) {
            String username = "member-" + i;
            usernames.add(username);
            XECKeyPair idKey = X25519Utils.newKeyPair();
            XECKeyPair ephemeralKey = X25519Utils.newKeyPair();
            theirIdKeys.put(username, idKey.getPublic());
            theirEphemeralKeys.put(username, ephemeralKey.getPublic());
            memberIdKeys.put(username, idKey);
            memberEphemeralKeys.put(username, ephemeralKey);
        }
        leaves = DHTree.setupLeavesNode(
                "admin",
                adminIdKey,
                setupKey,
                usernames,
                theirIdKeys,
                theirEphemeralKeys
        );
    }

    @Test
    void testLeftTreeSize() {
        int n = DHTree.leftTreeSize(1);
        assertEquals(0, n);
    }

    @Test
    void testSerializationTree() {
        Node root = DHTree.buildSecretTree(leaves);
        String json = toJson(root);
        Node publicRoot = toTree(json);
        String jsonTest = toJson(publicRoot);
        assertEquals(json, jsonTest);
    }

    /**
     * test khóa nút gốc admin tạo và các thành viên khác tạo
     */
    @Test
    void testRebuildSecretTree() {
        Node secretTree = DHTree.buildSecretTree(leaves);
        String json = toJson(secretTree);
        Node publicTree = DHTree.buildPublicTree(json);
        LeafNode secretLeaf = DHTree.findLeafNode(member, publicTree);
        XECKeyPair keyPair = CryptoUtils.recomputeExchangeKey(
                memberIdKeys.get(member),
                adminIdKey.getPublic(),
                memberEphemeralKeys.get(member),
                setupKey.getPublic()
        );
        secretLeaf.setKeyPair(keyPair);
        publicTree = DHTree.rebuildSecretTree(secretLeaf);
        assertArrayEquals(
                DHTree.getGroupKey(secretTree),
                DHTree.getGroupKey(publicTree)
        );
    }

    @Test
    void testUpdateKey() {
        // admin tạo cây DHTree
        Node secretTree = DHTree.buildSecretTree(leaves);
        // serialized cây để gửi đến các thành viên
        String json = toJson(secretTree);
        // member-1 nhận thông tin cy công khai
        Node tree2 = DHTree.buildPublicTree(json);
        // member-1 tìm vị trí node lá của mình trong cây
        LeafNode secretLeaf2 = DHTree.findLeafNode("member-1", tree2);
        // member-1 tạo ra 1 cặp key mới đẻ gửi tin nhắn
        XECKeyPair newEphemeralKey2 = X25519Utils.newKeyPair();
        // member-1 tính toán lại cây vầ public path
        secretLeaf2.setKeyPair(newEphemeralKey2);
        Queue<BigInteger> path = new LinkedList<>();
        DHTree.createPublicPath(secretLeaf2, path);
        // member-3 nhận thông tin cây từ admin
        Node publicTree4 = DHTree.buildPublicTree(json);
        LeafNode secretLeaf4 = DHTree.findLeafNode("member-3", publicTree4);
        XECKeyPair keyPair = CryptoUtils.recomputeExchangeKey(
                memberIdKeys.get("member-3"),
                adminIdKey.getPublic(),
                memberEphemeralKeys.get("member-3"),
                setupKey.getPublic()
        );
        secretLeaf4.setKeyPair(keyPair);
        // xây dưng lại cây cho member 3
        Node tree4 = DHTree.rebuildSecretTree(secretLeaf4);
        // tìm node member-1 trên cây member-3
        LeafNode leaf2 = DHTree.findLeafNode("member-1", tree4);
        // update the path
        DHTree.updatePath(leaf2, path);
        // so sánh khóa root của member-1 và member-3
        assertArrayEquals(
                DHTree.getGroupKey(tree2),
                DHTree.getGroupKey(publicTree4)
        );
    }
}