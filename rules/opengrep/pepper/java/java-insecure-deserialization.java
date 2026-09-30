import java.io.*;
import java.beans.XMLDecoder;
public class Deser {
  Object a(InputStream raw) throws Exception {
    ObjectInputStream in = new ObjectInputStream(raw);
    // ruleid: pepper.java.insecure-deserialization
    return in.readObject();
  }
  Object b(InputStream raw) throws Exception {
    // ruleid: pepper.java.insecure-deserialization
    return new XMLDecoder(raw).readObject();
  }
  Object c(InputStream raw) throws Exception {
    ObjectInputStream in = new ObjectInputStream(raw);
    in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.*;!*"));
    // ok: pepper.java.insecure-deserialization
    return in.readObject();
  }
}
