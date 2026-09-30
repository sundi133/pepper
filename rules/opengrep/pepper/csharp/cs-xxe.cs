using System.Xml;
public class Xml {
  public void A(string xml) {
    var doc = new XmlDocument();
    // ruleid: pepper.csharp.xxe
    doc.XmlResolver = new XmlUrlResolver();
    doc.LoadXml(xml);
    // ruleid: pepper.csharp.xxe
    var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
    // ok: pepper.csharp.xxe
    var safe = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
  }
}
