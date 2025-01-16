package art.example.groupchat.core.crypto;

import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;

/**
 * lớp XECKeyPair để lưu trữ cặp khóa ECC gồm khóa công khai và khóa riêng tư trên đường cong x25519
 */
public class XECKeyPair {
    private final XECPublicKey publicKey;
    private final XECPrivateKey privateKey;

    public XECKeyPair(XECPublicKey publicKey, XECPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public XECPublicKey getPublic() {
        return publicKey;
    }

    public XECPrivateKey getPrivate() {
        return privateKey;
    }
}
