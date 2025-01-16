package art.example.groupchat.core.tree;

import art.example.groupchat.core.crypto.XECKeyPair;


public abstract class Node {

    private transient XECKeyPair keyPair;
    private ParentNode parent;
    private Node sibling;

    public XECKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(XECKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public ParentNode getParent() {
        return parent;
    }

    public void setParent(ParentNode parent) {
        this.parent = parent;
    }

    public Node getSibling() {
        return sibling;
    }

    public void setSibling(Node sibling) {
        this.sibling = sibling;
    }

    abstract int numLeaves();
}
