import javax.xml.parsers.*;
import javax.xml.stream.*;
public class Xml {
  void a(java.io.InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // ruleid: pepper.java.xxe
    dbf.newDocumentBuilder().parse(in);
  }
  void b(java.io.InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // ok: pepper.java.xxe
    dbf.newDocumentBuilder().parse(in);
  }
  void c(java.io.InputStream in) throws Exception {
    XMLInputFactory xif = XMLInputFactory.newInstance();
    // ruleid: pepper.java.xxe
    xif.createXMLStreamReader(in);
  }
  void d(java.io.InputStream in) throws Exception {
    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    // ok: pepper.java.xxe
    xif.createXMLStreamReader(in);
  }
}
