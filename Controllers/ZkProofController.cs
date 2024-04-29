using System;
using System.Threading.Tasks;
using Grains;
using Microsoft.AspNetCore.Mvc;
using Orleans;
using ZkProof.Grains;

namespace ZkProof.Controllers
{
    [ApiController]
    [Route("proof")]
    public class ZkProofController : ControllerBase
    {
        private readonly IClusterClient _client;

        public ZkProofController(IClusterClient client)
        {
            _client = client;
        }

        [HttpPost("generate")]
        public async Task<ProofGenerationResponse> Generate(ProofGenerationRequest request)
        {
            var zkProofGrain = _client.GetGrain<IZkProofGrain>("zk-proof");
            var res = await zkProofGrain.Generate(request.Jwt, request.Salt);

            return new ProofGenerationResponse
            {
                Proof = res.Proof,
                IdentifierHash = res.IdentifierHash,
                PublicKey = res.PublicKey
            };
        }
        
        [HttpPost("initialize")]
        public async Task<bool> Initialize(InitializeRequest request)
        {
            var publicKey = String.IsNullOrEmpty(request.PublicKey) ? "pbk" : request.PublicKey;
            var zkProofGrain = _client.GetGrain<IZkProofGrain>("zk-proof");
            var res = await zkProofGrain.Initialize(request.Ip, publicKey);

            return res;
        }
        
        [HttpPost("login")]
        public async Task<ProofLoginInResponse> Login(ProofLoginInRequest request)
        {
            var zkProofGrain = _client.GetGrain<IZkProofGrain>("zk-proof");
            var res = await zkProofGrain.Login(request.Proof, request.IdentifierHash, request.PublicKey, request.ManagerAddress, request.Salt);

            return new ProofLoginInResponse
            {
                CaAddress = res.CaAddress,
                CaCash = res.CaCash
            };
        }
    }
}