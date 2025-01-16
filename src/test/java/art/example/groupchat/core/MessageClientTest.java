package art.example.groupchat.core;

import org.junit.jupiter.api.Test;

import java.security.interfaces.XECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class MessageClientTest {

    @Test
    void testChat() {
        MessageClient admin = new MessageClient("admin");
        MessageClient alice = new MessageClient("alice");
        MessageClient bob = new MessageClient("bob");
        MessageClient charlie = new MessageClient("charlie");
        MessageClient duke = new MessageClient("duke");
        //MessageClient tien = new MessageClient("tien");
        admin.creatNewGroup(0);

        XECPublicKey alicePubKey = alice.joinGroup(0);
        XECPublicKey bobPubKey = bob.joinGroup(0);
        XECPublicKey charliePubKey = charlie.joinGroup(0);
        XECPublicKey dukePubKey = duke.joinGroup(0);
        // XECPublicKey tienPubKey = tien.joinGroup(0);

        admin.addMember(0, "alice",
                alice.getIdKey(), alicePubKey);
        admin.addMember(0, "bob",
                bob.getIdKey(), bobPubKey);
        admin.addMember(0, "charlie",
                charlie.getIdKey(), charliePubKey);
        // admin.addMember(0, "tien", tien.getIdKey(), tienPubKey);
        String setupMsg = admin.addMember(0, "duke",
                duke.getIdKey(), dukePubKey);
         System.out.println("setupMsg" + setupMsg);
        alice.receiveSetupMessage(setupMsg);
        bob.receiveSetupMessage(setupMsg);
        charlie.receiveSetupMessage(setupMsg);
        duke.receiveSetupMessage(setupMsg);
//        tien.receiveSetupMessage(setupMsg);

        String plainMsg = "Hello group";

        String message = bob.sendMessage(0, plainMsg);
        System.out.println("message: " + message);
        String decrypted = alice.receiveMessage(message);
        assertEquals(plainMsg, decrypted);

        duke.receiveMessage(message);
        String anotherMsg = duke.sendMessage(0, "Good night");

        String anotherDecrypted = bob.receiveMessage(anotherMsg);
//        System.out.println(anotherDecrypted);
        assertEquals("Good night", anotherDecrypted);

//         String newSetupMsg = admin.removeMember(0, "bob");
//         System.out.println("setUpMsg: " + setupMsg);
//         System.out.println("newSetupMsg: " + newSetupMsg);

//        alice.receiveSetupMessage(newSetupMsg);
//        charlie.receiveSetupMessage(newSetupMsg);
//        duke.receiveSetupMessage(newSetupMsg);

//        String newmessage = bob.sendMessage(0, plainMsg);
//        System.out.println("message: " + newmessage);
//        String newdecrypted = bob.receiveMessage(newmessage);
//        assertEquals(plainMsg, newdecrypted);
    }

}