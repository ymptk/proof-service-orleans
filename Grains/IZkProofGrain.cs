using System.Threading.Tasks;
using Orleans;
using ZkProof.Grains;

namespace Grains;

public interface IZkProofGrain : IGrainWithStringKey
{
    Task<ProofGenerationResponse> Generate(string jwt, string salt);
    Task<bool> Initialize(string ip, string publicKey);
    Task<ProofLoginInResponse> Login(string proof, string identifierHash, string publicKeyHex,
        string managerAddress, string salt);
}