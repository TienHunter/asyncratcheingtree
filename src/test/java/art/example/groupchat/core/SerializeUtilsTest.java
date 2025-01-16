package art.example.groupchat.core;

import org.junit.jupiter.api.Test;
import art.example.groupchat.core.crypto.X25519Utils;
import art.example.groupchat.core.crypto.XECKeyPair;
import art.example.groupchat.core.serialize.SerializeUtils;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SerializeUtilsTest {

    @Test
    void testQueueToJson() {
        Queue<BigInteger> queue = new LinkedList<>();
        queue.add(BigInteger.valueOf(123456789));
        queue.add(BigInteger.valueOf(987654321));
        queue.add(BigInteger.valueOf(741852963));
        queue.add(BigInteger.valueOf(369258147));

        String json = SerializeUtils.toJson(queue);

        Queue<BigInteger> result = SerializeUtils.toQueue(json);

        result.poll();

        assertEquals(0, Objects.requireNonNull(result.poll()).compareTo(BigInteger.valueOf(987654321)));
    }


    @Test
    void toMap() {
        Map<String, XECPublicKey> map = new HashMap<>();
        XECKeyPair keyPair1 = X25519Utils.newKeyPair();
        XECKeyPair keyPair2 = X25519Utils.newKeyPair();
        XECKeyPair keyPair3 = X25519Utils.newKeyPair();
        XECKeyPair keyPair4 = X25519Utils.newKeyPair();

        map.put("member1", keyPair1.getPublic());
        map.put("member2", keyPair2.getPublic());
        map.put("member3", keyPair3.getPublic());
        map.put("member4", keyPair4.getPublic());

        String json = SerializeUtils.toJson(map);

        System.out.println(json);

        Map<String, XECPublicKey> deserialize = SerializeUtils.toMap(json);

        assertArrayEquals(
                map.get("member4").getEncoded(),
                deserialize.get("member4").getEncoded()
        );
    }
}