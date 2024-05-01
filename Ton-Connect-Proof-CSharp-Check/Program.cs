using System.Security.Cryptography;
using System.Text;
using Chaos.NaCl;

namespace Ton_Connect_Proof_CSharp_Check;

class Program
{
    private const string TonProofPrefix = "ton-proof-item-v2/";
    private const string TonConnectPrefix = "ton-connect";

    static void Main(string[] args)
    {
        CheckProof(new TonConnectMessage(), "YourPublicKey");
    }

    private static bool CheckProof(TonConnectMessage tonConnectMessage, string publicKey)
    {
        var addressBytes = Convert.FromHexString(tonConnectMessage.Address[2..]);
        var wcBytes = BitConverter.GetBytes(int.Parse(tonConnectMessage.Address.Split(':')[0]));
        if (BitConverter.IsLittleEndian)
            Array.Reverse(wcBytes);

        var messageBytes = Encoding.UTF8.GetBytes(TonProofPrefix)
            .Concat(wcBytes)
            .Concat(addressBytes)
            .Concat(BitConverter.GetBytes(tonConnectMessage.Proof.Domain.Value.Length))
            .Concat(Encoding.UTF8.GetBytes(tonConnectMessage.Proof.Domain.Value))
            .Concat(BitConverter.GetBytes(tonConnectMessage.Proof.Timestamp))
            .Concat(Encoding.UTF8.GetBytes(tonConnectMessage.Proof.Payload))
            .ToArray();

        var prefix = new byte[] { 0xff, 0xff };
        var prefixedMessageBytes = prefix
            .Concat(Encoding.UTF8.GetBytes(TonConnectPrefix))
            .Concat(SHA256.HashData(messageBytes))
            .ToArray();

        var publicKeyBytes = Convert.FromHexString(publicKey);
        var signature = Convert.FromBase64String(tonConnectMessage.Proof.Signature);
        var isValid = Ed25519.Verify(signature, SHA256.HashData(prefixedMessageBytes), publicKeyBytes);

        return isValid;
    }
}

public class TonConnectMessage
{
    public string Address { get; set; }
    public string Network { get; set; }
    public TonProof Proof { get; set; }
}

public class TonProof
{
    public long Timestamp { get; set; }
    public Domain Domain { get; set; }
    public string Signature { get; set; }
    public string Payload { get; set; }
    public string StateInit { get; set; }
}

public class Domain
{
    public int LengthBytes { get; set; }
    public string Value { get; set; }
}