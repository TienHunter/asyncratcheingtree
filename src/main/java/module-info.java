module soict.it2.groupchat {
    requires java.xml.bind;
    requires com.google.gson;

    opens art.example.groupchat;
    exports art.example.groupchat;
}