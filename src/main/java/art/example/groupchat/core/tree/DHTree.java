package art.example.groupchat.core.tree;

import art.example.groupchat.core.serialize.SerializeUtils;
import art.example.groupchat.core.crypto.CryptoUtils;
import art.example.groupchat.core.crypto.X25519Utils;
import art.example.groupchat.core.crypto.XECKeyPair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.XECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import static java.lang.Math.*;

/**
 *  cây Diffie-Hellman
 */
public class DHTree {

    /**
     * xây dựng nút lá của cây
     * @param username
     * @param adminIdKeys
     * @param memberIdKeys
     * @param setupKeys
     * @param memberEphemeralKey
     * @return
     */
    public static LeafNode buildLeaf(
            String username,
            XECKeyPair adminIdKeys,
            XECPublicKey memberIdKeys,
            XECKeyPair setupKeys,
            XECPublicKey memberEphemeralKey
    ) {
        // tính cặp khóa của node lá dựa trên khóa của admin, khóa thiết lập, và khóa công khai của người tham gia
        XECKeyPair keyPair = CryptoUtils.setupExchangeKey(
                adminIdKeys,
                memberIdKeys,
                setupKeys,
                memberEphemeralKey);
        return new LeafNode(username, keyPair);
    }

    /**
     * Group's admin compute {@link KeyPair} for each member
     *
     * @param admin              username of group's admin
     * @param adminIdKey         identity {@link KeyPair} of admin
     * @param setupKey           random {@link KeyPair} for new session
     * @param usernames          list member of group
     * @param theirIdKeys        list identity {@link XECPublicKey} of members
     * @param theirEphemeralKeys list ephemeral {@link XECPublicKey} of members for this session
     * @return list of leaf node in DH tree
     */
    public static List<LeafNode> setupLeavesNode(
            String admin,
            XECKeyPair adminIdKey,
            XECKeyPair setupKey,
            List<String> usernames,
            Map<String, XECPublicKey> theirIdKeys,
            Map<String, XECPublicKey> theirEphemeralKeys
    ) {
        List<LeafNode> leaves = new ArrayList<>();
        // add node leaf admin vào list leaves
        leaves.add(new LeafNode(admin, setupKey));
        usernames.remove(admin);
        for (String username : usernames) {
            XECPublicKey memberIdKey = theirIdKeys.get(username);
            XECPublicKey memberEphemeralKey = theirEphemeralKeys.get(username);
            leaves.add(buildLeaf(
                    username,
                    adminIdKey,
                    memberIdKey,
                    setupKey,
                    memberEphemeralKey
            ));
        }
        return leaves;
    }

    /**
     * Build a DH ratcheting tree from leaves
     *
     * @param secretLeaves list of {@link LeafNode}
     * @return root node of the tree, which contain shared secret
     */
    public static Node buildSecretTree(List<LeafNode> secretLeaves) {
        int n = secretLeaves.size();
        if (n == 0) throw new RuntimeException("No leaves");
        if (n == 1) return secretLeaves.get(0);

        // tính số lượng node lá code node left
        int l = leftTreeSize(n);
        // xây dựng cây bên trái
        Node left = buildSecretTree(secretLeaves.subList(0, l));

        // xây dựng cây bene phải
        Node right = buildSecretTree(secretLeaves.subList(l, n));

        return new ParentNode(left, right, true);
    }

    /**
     * Build a public tree from a secret tree by remove private key of each node, this public tree will be sent to all member to compute shared secret
     *
     * @param json the secret tree
     * @return root node of public tree
     */
    public static Node buildPublicTree(String json) {
        return SerializeUtils.toTree(json);
    }

    /**
     * Rebuild secret tree from its one secret {@link Node}
     *
     * @param secretNode a node contain private key
     * @return root node of secret tree
     */
    public static Node rebuildSecretTree(Node secretNode) {
        if (secretNode.getKeyPair().getPrivate() == null)
            throw new RuntimeException("Secret node must has private key");
        if (secretNode.getParent() == null) return secretNode;
        secretNode.getParent().computeKeyPair();
        return rebuildSecretTree(secretNode.getParent());
    }

    /**
     * ??
     * @param node
     * @return
     */
    public static byte[] getGroupKey(Node node) {
        return node.getKeyPair().getPrivate().getScalar().orElseThrow();
    }

    /**
     * tìm node lá
     * @param username
     * @param root
     * @return
     */
    public static LeafNode findLeafNode(String username, Node root) {
        if (root instanceof LeafNode) {
            if (((LeafNode) root).getUsername().equals(username)) return (LeafNode) root;
            return null;
        }
        if (root instanceof ParentNode) {
            LeafNode result = findLeafNode(username, ((ParentNode) root).getLeft());
            if (result != null) return result;
            return findLeafNode(username, ((ParentNode) root).getRight());
        }
        return null;
    }

    /**
     * tạo một đường dẫn công khai (public path) trong cây mật mã từ một nút con (child node) lên tới nút gốc (root node) của cây
     * create new key pair for sending new message and update public key to a path
     * @param child child node contain new key pair
     * @param updatedPath path contain new public key
     * @return root node
     */
    public static void createPublicPath(Node child, Queue<BigInteger> updatedPath) {
        updatedPath.add(child.getKeyPair().getPublic().getU());
        if (child.getParent() == null) return;
        child.getParent().computeKeyPair();
        createPublicPath(child.getParent(), updatedPath);
    }

    /**
     * cập nhật khóa công khai (public key) trong một cây mật mã
     * chưa hiểu ý nghĩa ??
     * @param child
     * @param path
     */
    public static void updatePath(Node child, Queue<BigInteger> path) {
        // lấy phần tử đầu tiên orong queue
        BigInteger u = path.peek();

        // lấy khóa công khai từ u
        XECPublicKey publicKey = X25519Utils.fromU(u);

        child.setKeyPair(new XECKeyPair(publicKey, null));

        if (child.getSibling().getKeyPair().getPrivate() != null) {
            rebuildSecretTree(child.getSibling());
            return;
        }

        path.poll();
        updatePath(child.getParent(), path);
    }

    /**
     * tính số lượng lá của node left
     * @param numLeaves
     * @return
     */
    public static int leftTreeSize(int numLeaves) {
        return (int) pow(2, (ceil(log(numLeaves) / log(2)) - 1));
    }


}
