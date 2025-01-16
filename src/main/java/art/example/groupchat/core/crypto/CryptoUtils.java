package art.example.groupchat.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;

/**
 * cung cấp các tiện ích để thực hiện các thao tác mã hóa và mật mã như hash, mã hóa/ giải m, tạo khóa trao đổi..
 */
public class CryptoUtils {

    /**
     * Tạo một đối tượng MessageDigest sử dụng thuật toán SHA-256 để tính hash
     * @return
     */
    public static MessageDigest startSHA256() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md;
    }

    /**
     * Tính HMAC (Hash-based Message Authentication Code) sử dụng thuật toán SHA-256.
     * @param data
     * @param key
     * @return
     */
    public static byte[] hmacSha256(byte[] data, byte[] key) {
        Mac mac;
        byte[] result = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
            // khởi tạo đối tượng mac với khóa bí mật
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(data);
            // Thực hiện tính toán HMAC và trả về giá trị HMAC dưới dạng mảng byte
            result = mac.doFinal();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Triển khai thuật toán HKDF (HMAC-based Key Derivation Function), giúp dẫn xuất khóa mật mã từ khóa gốc.
     * @param input_keying_material
     * @param salt
     * @param info
     * @param num_bytes
     * @return
     */
    public static byte[] hkdf(byte[] input_keying_material, byte[] salt, byte[] info, int num_bytes) {
        // Extract step
        byte[] pseudo_random_key = hmacSha256(salt, input_keying_material);

        // Expand step
        byte[] output_bytes = new byte[num_bytes];
        byte[] t = new byte[0];
        for (byte i = 0; i < (num_bytes + 31) / 32; i++) {
            byte[] tInput = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, tInput, 0, t.length);
            System.arraycopy(info, 0, tInput, t.length, info.length);
            tInput[tInput.length - 1] = i;

            t = hmacSha256(pseudo_random_key, tInput);
            int num_to_copy = num_bytes - (i * 32);
            if (num_to_copy > 32) {
                num_to_copy = 32;
            }

            System.arraycopy(t, 0, output_bytes, i * 32, num_to_copy);
        }
        return output_bytes;
    }

    /**
     * Sinh ra mảng byte ngẫu nhiên với độ dài n.
     * @param n
     * @return
     */
    public static byte[] randomBytes(int n) {
        byte[] result = new byte[n];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(result);
        return result;
    }

    /**
     * Mã hóa một thông điệp bằng AES ở chế độ GCM (Galois/Counter Mode).
     * @param message
     * @param keyBytes
     * @return
     */
    public static byte[] encrypt(byte[] message, byte[] keyBytes) {
        Cipher cipher;
        Key key;
        try {
            // sử dụng thuật toán mã hóa AES GCM NoPadding
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // tạo nonce
            byte[] nonce = randomBytes(12);
            GCMParameterSpec paramSpec = new GCMParameterSpec(16 * 8, nonce);

            // Chuyển đổi mảng byte keyBytes thành một đối tượng Key tương thích với thuật toán AES.
            key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

            // Xác định độ dài của dữ liệu sau khi mã hóa.
            int len = cipher.getOutputSize(message.length);
            System.out.println("len: " + len);
            byte[] result = new byte[len + 12];
            System.arraycopy(nonce, 0, result, 0, 12);

            //  Mã hóa dữ liệu đầu vào (message) và ghi kết quả vào mảng result, bắt đầu từ vị trí thứ 12 (sau Nonce).
            cipher.doFinal(
                    message,
                    0,
                    message.length,
                    result,
                    12
            );
            System.out.println("cipher: " + result.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * thực hiện giải mã một thông điệp đã được mã hóa bằng thuật toán AES-GCM, sử dụng khóa bí mật đã được cung cấp
     * @param encrypted
     * @param keyBytes
     * @return
     */
    public static byte[] decrypt(byte[] encrypted, byte[] keyBytes) {
        Cipher cipher;
        Key key;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");

            byte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(encrypted, 12, encrypted.length);
            GCMParameterSpec paramSpec = new GCMParameterSpec(16 * 8, nonce);

            key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     *  thực hiện một quá trình trao đổi khóa để tạo ra một khóa trao đổi (shared secret)
     * @param adminIdKeys: Cặp khóa (khóa công khai và khóa riêng tư) của quản trị viên
     * @param memberIdKey: Khóa công khai của thành viên.
     * @param setupKeys: Cặp khóa của bên thiết lập.
     * @param memberEphemeralKey: Khóa công khai tạm thời của thành viên (khóa công khai cho một phiên giao dịch cụ thể, thường thay đổi giữa các phiên).
     * @return
     */
    public static XECKeyPair setupExchangeKey(
            XECKeyPair adminIdKeys,
            XECPublicKey memberIdKey,
            XECKeyPair setupKeys,
            XECPublicKey memberEphemeralKey
    ) {
        MessageDigest md = startSHA256();
        // Trao đổi giữa quản trị viên và thành viên.
        md.update(X25519Utils.exchange(adminIdKeys, memberIdKey));
        // Trao đổi giữa quản trị viên và khóa công khai tạm thời của thành viên.
        md.update(X25519Utils.exchange(adminIdKeys, memberEphemeralKey));
        // Trao đổi giữa các khóa thiết lập và khóa công khai của thành viên.
        md.update(X25519Utils.exchange(setupKeys, memberIdKey));
        // Trao đổi giữa các khóa thiết lập và khóa công khai của thành viên.
        md.update(X25519Utils.exchange(setupKeys, memberEphemeralKey));

        byte[] raw = md.digest();
        return X25519Utils.fromPrivateKey(raw);
    }

    /**
     *
     * @param selfIdKeys: Cặp khóa ID riêng của người sử dụng
     * @param adminIdKey: Khóa công khai của admin.
     * @param selfEphemeralKeys: Cặp khóa tạm thời (ephemeral keys) của người sử dụng.
     * @param setupKey: Khóa công khai dùng trong quá trình thiết lập
     * @return
     */
    public static XECKeyPair recomputeExchangeKey(
            XECKeyPair selfIdKeys,
            XECPublicKey adminIdKey,
            XECKeyPair selfEphemeralKeys,
            XECPublicKey setupKey
    ) {
        MessageDigest md = startSHA256();
        md.update(X25519Utils.exchange(selfIdKeys, adminIdKey));
        md.update(X25519Utils.exchange(selfEphemeralKeys, adminIdKey));
        md.update(X25519Utils.exchange(selfIdKeys, setupKey));
        md.update(X25519Utils.exchange(selfEphemeralKeys, setupKey));
        byte[] raw = md.digest();
        return X25519Utils.fromPrivateKey(raw);
    }

}
