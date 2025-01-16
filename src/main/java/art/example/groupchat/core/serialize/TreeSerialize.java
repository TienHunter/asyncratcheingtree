package art.example.groupchat.core.serialize;

import com.google.gson.*;
import art.example.groupchat.core.crypto.X25519Utils;
import art.example.groupchat.core.crypto.XECKeyPair;
import art.example.groupchat.core.tree.LeafNode;
import art.example.groupchat.core.tree.Node;
import art.example.groupchat.core.tree.ParentNode;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;

public class TreeSerialize implements JsonSerializer<Node>, JsonDeserializer<Node> {

    @Override
    public JsonElement serialize(Node node, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject json = new JsonObject();
        XECPublicKey publicKey = node.getKeyPair().getPublic();
        json.addProperty("publicKey", publicKey.getU());
        if (node instanceof ParentNode) {
            Node left = ((ParentNode) node).getLeft();
            Node right = ((ParentNode) node).getRight();
            json.add("left", context.serialize(left, Node.class));
            json.add("right", context.serialize(right, Node.class));
        }
        if (node instanceof LeafNode) {
            json.addProperty("username", ((LeafNode) node).getUsername());
        }
        return json;
    }

    @Override
    public Node deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonElement username = json.getAsJsonObject().get("username");
        JsonElement jsonPublicKey = json.getAsJsonObject().get("publicKey");
        BigInteger u = jsonPublicKey == null ? null : jsonPublicKey.getAsBigInteger();
        XECPublicKey publicKey = X25519Utils.fromU(u);

        if (username == null) {
            Node left = context.deserialize(json.getAsJsonObject().get("left"), Node.class);
            Node right = context.deserialize(json.getAsJsonObject().get("right"), Node.class);
            ParentNode parentNode = new ParentNode(left, right, false);
            parentNode.setKeyPair(new XECKeyPair(publicKey, null));
            return parentNode;
        }

        return new LeafNode(username.getAsString(),
                new XECKeyPair(publicKey, null));
    }
}
