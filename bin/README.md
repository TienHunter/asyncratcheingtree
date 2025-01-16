# AsynRatchetingTree

This project is a simple implement of [Asynchronous Ratcheting Trees](https://eprint.iacr.org/2017/666.pdf) (ART), which is used for private messaging group

## How to run

- You must install JUnit and other dependencies which defined in pom.xml, although this project written most by [Java's standard crypto libraries](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190),
it also need some dependencies for convert between byte array and hex string, serialize message to json format in order to send it among group's member...

- The main concept of ART is implemented in DHTree.class, and client end-point in MessageClient.java. I simulate a conversation of a group in MessageClientTest.java so you need JUnit 5 to run that test.
