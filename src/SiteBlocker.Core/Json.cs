using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SiteBlocker.Core;

/// <summary>Единые настройки сериализации JSON (отступы, кириллица как есть, без лишнего экранирования).</summary>
public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
    private static readonly JsonSerializerOptions Compact = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize<T>(T value, bool indented = true) => JsonSerializer.Serialize(value, indented ? Options : Compact);
    public static T? Deserialize<T>(string text) => JsonSerializer.Deserialize<T>(text, Options);
    public static JsonNode? ToNode<T>(T value) => JsonSerializer.SerializeToNode(value, Options);
}
