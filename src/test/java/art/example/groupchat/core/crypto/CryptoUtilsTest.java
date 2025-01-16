package art.example.groupchat.core.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilsTest {


    /**
     * test trao đổi 1 cặp khóa
     */
    @Test
    void testExchange() {
        XECKeyPair adminId = X25519Utils.newKeyPair();
        XECKeyPair memberId = X25519Utils.newKeyPair();
        byte[] first = X25519Utils.exchange(adminId, memberId.getPublic());
        byte[] second = X25519Utils.exchange(memberId, adminId.getPublic());
        assertArrayEquals(first, second);
    }

    /**
     * test trao đổi khóa trong DHTree
     */
    @Test
    void computeKeyPairExchange() {
        XECKeyPair adminId = X25519Utils.newKeyPair();
        XECKeyPair setupKey = X25519Utils.newKeyPair();
        XECKeyPair memberId = X25519Utils.newKeyPair();
        XECKeyPair ephemeral = X25519Utils.newKeyPair();
        XECKeyPair exchange1 = CryptoUtils.setupExchangeKey(
                adminId,
                memberId.getPublic(),
                setupKey,
                ephemeral.getPublic()
        );
        XECKeyPair exchange2 = CryptoUtils.recomputeExchangeKey(
                memberId,
                adminId.getPublic(),
                ephemeral,
                setupKey.getPublic()
        );
        assertEquals(0, exchange1.getPublic().getU().compareTo(exchange2.getPublic().getU()));
    }
}