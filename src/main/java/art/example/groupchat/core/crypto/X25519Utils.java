package art.example.groupchat.core.crypto;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * cung cấp các tiên ích dùng để xử lý các thao tác mật mã với đường cong x25519
 */
public class X25519Utils {

    /**
     * tính shared secret dựa trên khóa bí mật của mình và khóa công khai của người khác dựa trên thuật toán X25519
     * @param myKeyPair
     * @param theirPublicKey
     * @return
     */
    public static byte[] exchange(XECKeyPair myKeyPair, XECPublicKey theirPublicKey) {
        KeyAgreement keyAgreement;
        try {
            // tạo một phiên keyAgreement sử dụng thuật toán XDH
            keyAgreement = KeyAgreement.getInstance("XDH");
            // Khởi tạo với khóa riêng
            keyAgreement.init(myKeyPair.getPrivate());
            // Xử lý khóa công khai của bên kia
            keyAgreement.doPhase(theirPublicKey, true);
            // trả về là "shared secret"
            return keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * tạo một cặp khóa mới
     * @return
     */
    public static XECKeyPair newKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            // sử dụng x25519 để sinh khóa
            generator.initialize(NamedParameterSpec.X25519);
            KeyPair keyPair = generator.genKeyPair();
            return new XECKeyPair((XECPublicKey) keyPair.getPublic(), (XECPrivateKey) keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * khôi phục cặp khóa từ khóa riêng
     * @param privateKey
     * @return
     */
    public static XECKeyPair fromPrivateKey(XECPrivateKey privateKey) {
        byte[] rawPrivateKey = privateKey.getScalar().orElseThrow();
        return fromPrivateKey(rawPrivateKey);
    }

    /**
     * khôi phục laại cặp khóa dựa trên khóa riêng
     * @param rawPrivateKey
     * @return
     */
    public static XECKeyPair fromPrivateKey(byte[] rawPrivateKey) {
        if (rawPrivateKey.length != 32) {
            throw new RuntimeException("Private key length must be 32");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            generator.initialize(NamedParameterSpec.X25519, new StaticSecureRandom(rawPrivateKey));
            KeyPair keyPair = generator.genKeyPair();
            return new XECKeyPair((XECPublicKey) keyPair.getPublic(), (XECPrivateKey) keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * khôi phục khóa công khai từ tọa độ u trên đường cong x25519
     * @param u
     * @return
     */
    public static XECPublicKey fromU(BigInteger u) {
        try {
            if (u == null) return null;
            return (XECPublicKey) KeyFactory
                    .getInstance("X25519")
                    .generatePublic(
                            new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Chuyển đổi một khóa riêng từ chuỗi hex.
     * @param hex
     * @return
     */
    public static XECPrivateKey fromHex(String hex) {
        return fromBytes(DatatypeConverter.parseHexBinary(hex));
    }

    public static XECPrivateKey fromBytes(byte[] bytes) {
        try {
            return (XECPrivateKey) KeyFactory
                    .getInstance("X25519")
                    .generatePrivate(
                            new XECPrivateKeySpec(NamedParameterSpec.X25519, bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
