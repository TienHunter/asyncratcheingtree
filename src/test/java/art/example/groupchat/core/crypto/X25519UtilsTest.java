package art.example.groupchat.core.crypto;

import org.junit.jupiter.api.Test;

import java.security.interfaces.XECPrivateKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class X25519UtilsTest {

    @Test
    void x25519KeyPair() {
        XECKeyPair keyPair = X25519Utils.newKeyPair();
        XECPrivateKey privateKey = keyPair.getPrivate();
        XECKeyPair newKeyPair = X25519Utils.fromPrivateKey(privateKey);
        System.out.println(keyPair.getPublic().getEncoded().length);
        System.out.println(keyPair.getPrivate().getScalar().orElseThrow().length);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), newKeyPair.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), newKeyPair.getPublic().getEncoded());
    }

    @Test
    void keyAgreement() {
        XECKeyPair alice = X25519Utils.newKeyPair();
        XECKeyPair bob = X25519Utils.newKeyPair();
        byte[] sk = X25519Utils.exchange(alice, bob.getPublic());
        assertEquals(sk.length, 32);
        XECKeyPair newKeyPair = X25519Utils.fromPrivateKey(sk);
        assertEquals(newKeyPair.getPrivate().getScalar().orElseThrow().length, 32);
    }
}