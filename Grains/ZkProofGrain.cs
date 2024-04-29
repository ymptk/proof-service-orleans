using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AElf;
using AElf.Client;
using AElf.Client.Dto;
using AElf.Types;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Groth16.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Orleans;
using Portkey.Contracts.CA;
using ProofService.interfaces;
using RestSharp;
using ZkProof.Grains;
using ZkVerifier;

namespace Grains;

public class ZkProofGrain : Grain, IZkProofGrain
{
    // private readonly IPersistentState<ZkProofState> _zkProofState;
    private readonly ILogger<ZkProofGrain> _logger;
    private readonly ZkProverSetting _proverSetting;
    private readonly ContractClient _contractClient;
    private Prover _prover;
    public bool isProverLoad;
    
    public ZkProofGrain(
        IOptions<ZkProverSetting> proverSetting,
        IOptions<ContractClient> contractClient,
        ILogger<ZkProofGrain> logger)
    {
        _logger = logger;
        _proverSetting = proverSetting.Value;
        _contractClient = contractClient.Value;
    }
    
    public async Task<ProofLoginInResponse> Login(string proof, string identifierHash, string publicKeyHex, string managerAddress, string salt)
    {
        try
        {
            // var proof = request.Proof;
            // var identifierHash = request.IdentifierHash;
            // var publicKeyHex = request.PublicKey;
            // var managerAddress = request.ManagerAddress;
            // var salt = request.Salt;
            var walletAddress = _contractClient.WalletAddress;
            var caContractAddress = _contractClient.CaContractAddress;
            var pk = _contractClient.PK;
            var client = new AElfClient(_contractClient.IP);

            // get holder info to check whether needs to create new holder
            GetHolderInfoOutput holderInfo = null;
            try
            {
                holderInfo = await GetCaHolder(client, caContractAddress, pk, identifierHash, walletAddress);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("Not found ca_hash"))
                {
                    _logger.LogWarning("Not found ca_hash");
                }
                else
                {
                    throw;
                }
            }

            // if holder is not null, just needs to add manager address
            if (holderInfo != null)
            {
                await AddCaManager(client, caContractAddress, pk, holderInfo.CaHash, managerAddress);
                var response = new ProofLoginInResponse
                {
                    CaCash = holderInfo.CaHash.ToHex(),
                    CaAddress = holderInfo.CaAddress.ToBase58(),
                };
                return response;
            }
            // if holder is null, just needs to create holder and add manager address
            else
            {
                // add new public key to zkIssuer
                await AddZkIssuerPublicKey(client, caContractAddress, pk, identifierHash, walletAddress, salt, publicKeyHex, proof);
                // await InitializeAsync(ip, endpoint, caContractAddress, walletAddress, pk, publicKeyHex, zkVk);
                var result = await CreateCaHolder(client, caContractAddress, pk, identifierHash, walletAddress, salt, publicKeyHex, proof);
                
                var newHolderInfo = await GetCaHolder(client, caContractAddress, pk, identifierHash, walletAddress);
                await AddCaManager(client, caContractAddress, pk, newHolderInfo.CaHash, managerAddress);

                var response = new ProofLoginInResponse
                {
                    CaCash = newHolderInfo.CaHash.ToHex(),
                    CaAddress = newHolderInfo.CaAddress.ToBase58(),
                };

                return response;
            }
        }
        catch (Exception e)
        {
            _logger.LogError("login exception, e: {msg}", e.Message);
            throw;
        }
    }

    public async Task<bool> Initialize(string ip, string publicKey)
    {
        try
        {
            var endpoint = ip;
            if (!isProverLoad)
            {
                _logger.LogInformation("Loading prover file......");
                _prover = Prover.Create(_proverSetting.WasmPath, _proverSetting.R1csPath, _proverSetting.ZkeyPath);
                isProverLoad = true;
                _logger.LogInformation("Loading prover file completed");
            }
            var zkVk = _prover.ExportVerifyingKeyBn254();
            var res = await InitializeAsync(ip, endpoint, _contractClient.CaContractAddress, _contractClient.WalletAddress,
                _contractClient.PK, publicKey, zkVk);
            return res;
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            throw;
        }
    }
    
    public async Task<ProofGenerationResponse> Generate(string jwt, string salt)
    {
        if (!isProverLoad)
        {
            _logger.LogInformation("Loading prover file......");
            _prover = Prover.Create(_proverSetting.WasmPath, _proverSetting.R1csPath, _proverSetting.ZkeyPath);
            isProverLoad = true;
            _logger.LogInformation("Loading prover file completed");
        }

        var res = await Generate(jwt, salt, _prover);
        return res;
    }

    public async Task<ProofGenerationResponse> Generate(string jwtStr, string saltStr, Prover _prover)
    {
        try
        {
            var jwtHeader = jwtStr.Split(".")[0];
            var jwtPayload = jwtStr.Split(".")[1];
            var jwtSignature = jwtStr.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(jwtStr);

            // get google public key from jwt
            var publicKey = await GetGooglePublicKeyFromJwt(jwt);
            // google public key to hex
            var publicKeyHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(publicKey)).Replace("-", "")
                .ToLower();
            // google public key hex to chunked bytes
            var pubkey = Helpers.HexToChunkedBytes(publicKeyHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // jwt signature to hex
            var signatureHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(jwtSignature)).Replace("-", "")
                .ToLower();
            // jwt signature hex to chunked bytes
            var signature = Helpers.HexToChunkedBytes(signatureHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // salt hex to chunked bytes
            var salt = HexStringToByteArray(saltStr).Select(b => b.ToString()).ToList();

            var payloadStartIndex = jwtStr.IndexOf(".") + 1;
            var subClaim = PadString("\"sub\":" + "\"" + jwt.Payload.Sub + "\"" + ",", 41);
            var subClaimLength = jwt.Payload.Sub.Length + 9;
            var jsonString = ParseJwtPayload(jwtPayload);
            // the start index of field sub
            var startIndex = jsonString.IndexOf("\"sub\"");
            // the start index of field sub value
            var valueStartIndex = jsonString.IndexOf('"', startIndex + 5) + 1;
            // the end index of field sub value
            var valueEndIndex = jsonString.IndexOf('"', valueStartIndex);
            var subIndexB64 = payloadStartIndex + startIndex * 4 / 3;
            var subLengthB64 = (valueEndIndex + 2 - (startIndex - 1)) * 4 / 3;
            var subNameLength = 5;
            var subColonIndex = 5;
            var subValueIndex = 6;
            var subValueLength = 23;

            // build parameters of ProveBn254
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = PadString(jwtHeader + "." + jwtPayload, 2048);
            provingInput["signature"] = signature;
            provingInput["pubkey"] = pubkey;
            provingInput["salt"] = salt;
            provingInput["payload_start_index"] = new List<string> {payloadStartIndex.ToString()};
            provingInput["sub_claim"] = subClaim;
            provingInput["sub_claim_length"] = new List<string> {subClaimLength.ToString()};
            provingInput["sub_index_b64"] = new List<string> {subIndexB64.ToString()};
            provingInput["sub_length_b64"] = new List<string> {subLengthB64.ToString()};
            provingInput["sub_name_length"] = new List<string> {subNameLength.ToString()};
            provingInput["sub_colon_index"] = new List<string> {subColonIndex.ToString()};
            provingInput["sub_value_index"] = new List<string> {subValueIndex.ToString()};
            provingInput["sub_value_length"] = new List<string> {subValueLength.ToString()};
            
            // exec ProveBn254
            _logger.LogInformation("Starting proof generation......");
            var provingOutputString = _prover.ProveBn254(provingInput);
            _logger.LogInformation("Completing proof generation");
            var provingOutput = ParseProvingOutput(provingOutputString);
            _logger.LogInformation("proof: " + provingOutput.Proof);
            return new ProofGenerationResponse
            {
                Proof = provingOutput.Proof,
                IdentifierHash =
                    GetGuardianIdentifierHashFromJwtPublicInputs(new List<string>(provingOutput.PublicInputs)),
                PublicKey = publicKeyHex
            };
        }
        catch (Exception e)
        {
            _logger.LogInformation("proof generate exception, e: ", e.Message);
            throw;
        }
    }

        #region private method

    private string ParseJwtPayload(string payload)
    {
        string padded = payload.Length % 4 == 0 ? payload : payload + "====".Substring(payload.Length % 4);
        string base64 = padded.Replace("_", "/").Replace("-", "+");
        byte[] outputb = Convert.FromBase64String(base64);
        string outStr = Encoding.Default.GetString(outputb);
        return outStr;
    }

    private byte[] HexStringToByteArray(string hex)
    {
        var length = hex.Length;
        var byteArray = new byte[length / 2];

        for (var i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return byteArray;
    }

    private string GetGuardianIdentifierHashFromJwtPublicInputs(List<string> publicInputs)
    {
        var idHash = publicInputs.GetRange(0, 32);
        var identifierHash = idHash.Select(s => byte.Parse(s)).ToArray();
        var guardianIdentifierHash = identifierHash.ToHex();
        return guardianIdentifierHash;
    }

    private async Task<string> GetGooglePublicKeyFromJwt(JwtSecurityToken jwt)
    {
        var options = new RestClientOptions("https://www.googleapis.com/oauth2/v3/certs");
        var client = new RestClient(options);
        var request = new RestRequest();
        var response = await client.GetAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            return "";
        }

        var res = (JObject) JsonConvert.DeserializeObject(response.Content);
        var keys = res["keys"];
        foreach (var key in keys)
        {
            var kid = key["kid"].ToString();
            if (jwt.Header.Kid == kid)
            {
                return key["n"].ToString();
            }
        }

        return "";
    }

    private ProvingOutput ParseProvingOutput(string provingOutput)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
    }

    private List<string> PadString(string str, int paddedBytesSize)
    {
        var paddedBytes = str.Select(c => ((int) c).ToString()).ToList();

        var paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }

    private async Task<bool> InitializeAsync(string ip, string endpoint, string contractAddress, string walletAddress,
        string pk, string publicKey, string vk)
    {
        AElfClient client = new AElfClient(ip);
        var isConnected = await client.IsConnectedAsync();
        if (!isConnected) return false;
        // var contractAddress = "";
        // var pk = "";

        var initializeInput = new InitializeInput
        {
            ContractAdmin = Address.FromBase58(walletAddress)
        };
        await SendTransaction(client, contractAddress, "Initialize", pk, initializeInput);

        var setCreateHolderEnabledInput = new SetCreateHolderEnabledInput
        {
            CreateHolderEnabled = true
        };
        await SendTransaction(client, contractAddress, "SetCreateHolderEnabled", pk, setCreateHolderEnabledInput);

        var issuerPublicKeyEntry = new IssuerPublicKeyEntry
        {
            IssuerName = "Google",
            IssuerPubkey = publicKey
        };
        await SendTransaction(client, contractAddress, "AddZkIssuer", pk, issuerPublicKeyEntry);

        var publicKeysBytes = await CallTransaction(client, walletAddress, contractAddress, "GetZkIssuerPublicKeyList", pk,
            new StringValue {Value = ""});
        var publicKeyList = PublicKeyList.Parser.ParseFrom(publicKeysBytes).PublicKeys;
        if (!publicKeyList.Contains(publicKey))
        {
            await SendTransaction(client, contractAddress, "AddZkIssuerPublicKey", pk, issuerPublicKeyEntry);
        }

        var addVerifierServerEndPointsInput = new AddVerifierServerEndPointsInput
        {
            Name = "Portkey",
            ImageUrl = "https://portkey-did.s3.ap-northeast-1.amazonaws.com/img/Portkey.png",
            EndPoints = {ip},
            VerifierAddressList = {Address.FromBase58(walletAddress)}
        };
        await SendTransaction(client, contractAddress, "AddVerifierServerEndPoints", pk,
            addVerifierServerEndPointsInput);

        var stringValue = new StringValue
        {
            Value = vk
        };
        await SendTransaction(client, contractAddress, "SetZkVerifiyingKey", pk, stringValue);
        return true;
    }

    private async Task<TransactionResultDto> AddCaManager(AElfClient client, string caContractAddress, string pk, Hash caHash, string managerAddress)
    {
        var addManagerInfoInput = new AddManagerInfoInput
        {
            CaHash = caHash,
            ManagerInfo = new ManagerInfo
            {
                Address = Address.FromBase58(managerAddress),
                ExtraData = "manager"
            }
        };
        return await SendTransaction(client, caContractAddress, "AddManagerInfo", pk, addManagerInfoInput);
    }
    
    private async Task<TransactionResultDto> RemoveCaManager(AElfClient client, string caContractAddress, string pk, Hash caHash, string managerAddress)
    {
        var removeManagerInfoInput = new RemoveManagerInfoInput()
        {
            CaHash = caHash
        };
        return await SendTransaction(client, caContractAddress, "RemoveManagerInfo", pk, removeManagerInfoInput);
    }

    private async Task<GetHolderInfoOutput> GetCaHolder(AElfClient client, string caContractAddress, string pk, string identifierHash, string walletAddress)
    {
        var holderInfoInput = new GetHolderInfoInput
        {
            LoginGuardianIdentifierHash = Hash.LoadFromHex(identifierHash)
        };
        return GetHolderInfoOutput.Parser.ParseFrom(await CallTransaction(client, walletAddress,
            caContractAddress, "GetHolderInfo", pk, holderInfoInput));
    }

    private async Task<TransactionResultDto> CreateCaHolder(AElfClient client, string caContractAddress, string pk,
        string identifierHash, string walletAddress, string salt, string publicKeyHex, string proof)
    {
        var createCAHolderInput = new CreateCAHolderInput()
        {
            GuardianApproved = new GuardianInfo
            {
                IdentifierHash = Hash.LoadFromHex(identifierHash),
                ZkGuardianInfo = new ZkGuardianInfo
                {
                    IdentifierHash = Hash.LoadFromHex(identifierHash),
                    Salt = salt,
                    IssuerName = "Google",
                    IssuerPubkey = publicKeyHex,
                    Proof = proof
                }
            },
            ManagerInfo = new ManagerInfo
            {
                Address = Address.FromBase58(walletAddress),
                ExtraData = "manager"
            }
        };
        return await SendTransaction(client, caContractAddress, "CreateCAHolder", pk, createCAHolderInput);
    }
    
    private async Task AddZkIssuerPublicKey(AElfClient client, string contractAddress, string pk,
        string identifierHash, string walletAddress, string salt, string publicKey, string proof)
    {
        var issuerPublicKeyEntry = new IssuerPublicKeyEntry
        {
            IssuerName = "Google",
            IssuerPubkey = publicKey
        };
        var publicKeysBytes = await CallTransaction(client, walletAddress, contractAddress, "GetZkIssuerPublicKeyList", pk,
            new StringValue {Value = ""});
        var publicKeyList = PublicKeyList.Parser.ParseFrom(publicKeysBytes).PublicKeys;
        if (!publicKeyList.Contains(publicKey))
        {
            await SendTransaction(client, contractAddress, "AddZkIssuerPublicKey", pk, issuerPublicKeyEntry);
        }
    }

    private async Task<TransactionResultDto> SendTransaction(AElfClient client, string contractAddress,
        string methodName, string pk,
        IMessage param)
    {
        // var tokenContractAddress = await client.GetContractAddressByNameAsync(HashHelper.ComputeFrom("AElf.ContractNames.Token"));
        // var methodName = "Transfer";
        // var param = new TransferInput
        // {
        //     To = new Address {Value = Address.FromBase58("7s4XoUHfPuqoZAwnTV7pHWZAaivMiL8aZrDSnY9brE1woa8vz").Value},
        //     Symbol = "ELF",
        //     Amount = 1000000000,
        //     Memo = "transfer in demo"
        // };
        var ownerAddress = client.GetAddressFromPrivateKey(pk);

        // Generate a transfer transaction.
        var transaction = await client.GenerateTransactionAsync(ownerAddress, contractAddress, methodName, param);
        var txWithSign = client.SignTransaction(pk, transaction);

        // Send the transfer transaction to AElf chain node.
        var result = await client.SendTransactionAsync(new SendTransactionInput
        {
            RawTransaction = txWithSign.ToByteArray().ToHex()
        });

        _logger.LogInformation(result.TransactionId);

        await Task.Delay(5000);
        // After the transaction is mined, query the execution results.
        var transactionResult = await client.GetTransactionResultAsync(result.TransactionId);
        _logger.LogInformation(transactionResult.Status != "MINED"
            ? methodName + ": " + result.TransactionId + ": " + transactionResult.Status + ": " +
              transactionResult.Error
            : methodName + ": " + result.TransactionId + ": " + transactionResult.Status);
        return transactionResult;
    }

    private async Task<byte[]> CallTransaction(AElfClient client, string walletAddress, string contractAddress,
        string methodName, string pk,
        IMessage param)
    {
        var transaction = await client.GenerateTransactionAsync(walletAddress, contractAddress, methodName, param);
        var txWithSign = client.SignTransaction(pk, transaction);
        var transactionResult = await client.ExecuteTransactionAsync(new ExecuteTransactionDto
        {
            RawTransaction = txWithSign.ToByteArray().ToHex()
        });
        return ByteArrayHelper.HexStringToByteArray(transactionResult);
    }

    #endregion


}

public class ProvingOutput
{
    public ProvingOutput(IList<string> publicInputs, string proof)
    {
        PublicInputs = publicInputs;
        Proof = proof;
    }

    [JsonProperty("public_inputs")] public IList<string> PublicInputs { get; set; }

    [JsonProperty("proof")] public string Proof { get; set; }

    public static ProvingOutput FromJsonString(string jsonString)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(jsonString);
    }
}