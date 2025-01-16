package art.example.groupchat.core.serialize;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import art.example.groupchat.core.Message;
import art.example.groupchat.core.SetupMessage;
import art.example.groupchat.core.crypto.X25519Utils;
import art.example.groupchat.core.tree.Node;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

public class SerializeUtils {


    public static final Gson gson = new GsonBuilder()
            .registerTypeAdapter(Node.class, new TreeSerialize())
            .setPrettyPrinting()
            .create();

    public static String toJson(Node root) {
        return gson.toJson(root);
    }

    public static Node toTree(String json) {
        return gson.fromJson(json, Node.class);
    }

    public static String toJson(Queue<BigInteger> queue) {
        return gson.toJson(queue);
    }

    public static Queue<BigInteger> toQueue(String json) {
        Type queueType = new TypeToken<LinkedList<BigInteger>>() {}.getType();
        return gson.fromJson(json, queueType);
    }

    public static String toJson(Map<String, XECPublicKey> map) {
        Map<String, BigInteger> uMap = new HashMap<>();
        for (Map.Entry<String, XECPublicKey> entry : map.entrySet()) {
            uMap.put(
                    entry.getKey(),
                    entry.getValue().getU()
            );
        }
        return gson.toJson(uMap);
    }

    public static Map<String, XECPublicKey> toMap(String json) {
        Map<String, XECPublicKey> result = new HashMap<>();
        Type mapType = new TypeToken<HashMap<String, BigInteger>>() {}.getType();
        Map<String, BigInteger> uMap = gson.fromJson(json, mapType);
        for (Map.Entry<String, BigInteger> entry : uMap.entrySet()) {
            XECPublicKey publicKey = X25519Utils.fromU(entry.getValue());
            result.put(entry.getKey(), publicKey);
        }
        return result;
    }

    public static String toJson(SetupMessage message) {
        return gson.toJson(message);
    }

    public static SetupMessage toSetupMessage(String json) {
        return gson.fromJson(json, SetupMessage.class);
    }

    public static String toJson(Message message) {
        return gson.toJson(message);
    }

    public static Message toMessage(String json) {
        return gson.fromJson(json, Message.class);
    }
}
