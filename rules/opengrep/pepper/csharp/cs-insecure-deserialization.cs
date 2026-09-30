using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;
public class Deser {
  public object A(System.IO.Stream s) {
    // ruleid: pepper.csharp.insecure-deserialization
    var bf = new BinaryFormatter();
    return bf.Deserialize(s);
  }
  public object B(string json) {
    // ruleid: pepper.csharp.insecure-deserialization
    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
    return JsonConvert.DeserializeObject(json, settings);
  }
  public object C(string json) {
    // ok: pepper.csharp.insecure-deserialization
    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
    return System.Text.Json.JsonSerializer.Deserialize<Order>(json);
  }
}
