// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: zk_verifier.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace ZkVerifier {

  /// <summary>Holder for reflection information generated from zk_verifier.proto</summary>
  public static partial class ZkVerifierReflection {

    #region Descriptor
    /// <summary>File descriptor for zk_verifier.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static ZkVerifierReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChF6a192ZXJpZmllci5wcm90bxILemtfdmVyaWZpZXIaG2dvb2dsZS9wcm90",
            "b2J1Zi9lbXB0eS5wcm90bxoeZ29vZ2xlL3Byb3RvYnVmL3dyYXBwZXJzLnBy",
            "b3RvGhJhZWxmL29wdGlvbnMucHJvdG8iQgoUSXNzdWVyUHVibGljS2V5RW50",
            "cnkSEwoLaXNzdWVyX25hbWUYASABKAkSFQoNaXNzdWVyX3B1YmtleRgCIAEo",
            "CSIkCg1QdWJsaWNLZXlMaXN0EhMKC3B1YmxpY19rZXlzGAEgAygJIh0KCklz",
            "c3Vlckxpc3QSDwoHaXNzdWVycxgBIAMoCTKMBQoKWmtWZXJpZmllchJICgtB",
            "ZGRaa0lzc3VlchIhLnprX3ZlcmlmaWVyLklzc3VlclB1YmxpY0tleUVudHJ5",
            "GhYuZ29vZ2xlLnByb3RvYnVmLkVtcHR5EkYKDlJlbW92ZVprSXNzdWVyEhwu",
            "Z29vZ2xlLnByb3RvYnVmLlN0cmluZ1ZhbHVlGhYuZ29vZ2xlLnByb3RvYnVm",
            "LkVtcHR5ElEKFEFkZFprSXNzdWVyUHVibGljS2V5EiEuemtfdmVyaWZpZXIu",
            "SXNzdWVyUHVibGljS2V5RW50cnkaFi5nb29nbGUucHJvdG9idWYuRW1wdHkS",
            "VAoXUmVtb3ZlWmtJc3N1ZXJQdWJsaWNLZXkSIS56a192ZXJpZmllci5Jc3N1",
            "ZXJQdWJsaWNLZXlFbnRyeRoWLmdvb2dsZS5wcm90b2J1Zi5FbXB0eRJKChJT",
            "ZXRaa1ZlcmlmaXlpbmdLZXkSHC5nb29nbGUucHJvdG9idWYuU3RyaW5nVmFs",
            "dWUaFi5nb29nbGUucHJvdG9idWYuRW1wdHkSWwoYR2V0WmtJc3N1ZXJQdWJs",
            "aWNLZXlMaXN0EhwuZ29vZ2xlLnByb3RvYnVmLlN0cmluZ1ZhbHVlGhouemtf",
            "dmVyaWZpZXIuUHVibGljS2V5TGlzdCIFiIn3AQESUQoSR2V0WmtWZXJpZml5",
            "aW5nS2V5EhYuZ29vZ2xlLnByb3RvYnVmLkVtcHR5GhwuZ29vZ2xlLnByb3Rv",
            "YnVmLlN0cmluZ1ZhbHVlIgWIifcBARJHCg1HZXRJc3N1ZXJMaXN0EhYuZ29v",
            "Z2xlLnByb3RvYnVmLkVtcHR5GhcuemtfdmVyaWZpZXIuSXNzdWVyTGlzdCIF",
            "iIn3AQFiBnByb3RvMw=="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { global::Google.Protobuf.WellKnownTypes.EmptyReflection.Descriptor, global::Google.Protobuf.WellKnownTypes.WrappersReflection.Descriptor, global::AElf.OptionsReflection.Descriptor, },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::ZkVerifier.IssuerPublicKeyEntry), global::ZkVerifier.IssuerPublicKeyEntry.Parser, new[]{ "IssuerName", "IssuerPubkey" }, null, null, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::ZkVerifier.PublicKeyList), global::ZkVerifier.PublicKeyList.Parser, new[]{ "PublicKeys" }, null, null, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::ZkVerifier.IssuerList), global::ZkVerifier.IssuerList.Parser, new[]{ "Issuers" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  public sealed partial class IssuerPublicKeyEntry : pb::IMessage<IssuerPublicKeyEntry>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<IssuerPublicKeyEntry> _parser = new pb::MessageParser<IssuerPublicKeyEntry>(() => new IssuerPublicKeyEntry());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<IssuerPublicKeyEntry> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::ZkVerifier.ZkVerifierReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerPublicKeyEntry() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerPublicKeyEntry(IssuerPublicKeyEntry other) : this() {
      issuerName_ = other.issuerName_;
      issuerPubkey_ = other.issuerPubkey_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerPublicKeyEntry Clone() {
      return new IssuerPublicKeyEntry(this);
    }

    /// <summary>Field number for the "issuer_name" field.</summary>
    public const int IssuerNameFieldNumber = 1;
    private string issuerName_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public string IssuerName {
      get { return issuerName_; }
      set {
        issuerName_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "issuer_pubkey" field.</summary>
    public const int IssuerPubkeyFieldNumber = 2;
    private string issuerPubkey_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public string IssuerPubkey {
      get { return issuerPubkey_; }
      set {
        issuerPubkey_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as IssuerPublicKeyEntry);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(IssuerPublicKeyEntry other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (IssuerName != other.IssuerName) return false;
      if (IssuerPubkey != other.IssuerPubkey) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (IssuerName.Length != 0) hash ^= IssuerName.GetHashCode();
      if (IssuerPubkey.Length != 0) hash ^= IssuerPubkey.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void WriteTo(pb::CodedOutputStream output) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      output.WriteRawMessage(this);
    #else
      if (IssuerName.Length != 0) {
        output.WriteRawTag(10);
        output.WriteString(IssuerName);
      }
      if (IssuerPubkey.Length != 0) {
        output.WriteRawTag(18);
        output.WriteString(IssuerPubkey);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
      if (IssuerName.Length != 0) {
        output.WriteRawTag(10);
        output.WriteString(IssuerName);
      }
      if (IssuerPubkey.Length != 0) {
        output.WriteRawTag(18);
        output.WriteString(IssuerPubkey);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(ref output);
      }
    }
    #endif

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int CalculateSize() {
      int size = 0;
      if (IssuerName.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(IssuerName);
      }
      if (IssuerPubkey.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(IssuerPubkey);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(IssuerPublicKeyEntry other) {
      if (other == null) {
        return;
      }
      if (other.IssuerName.Length != 0) {
        IssuerName = other.IssuerName;
      }
      if (other.IssuerPubkey.Length != 0) {
        IssuerPubkey = other.IssuerPubkey;
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(pb::CodedInputStream input) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      input.ReadRawMessage(this);
    #else
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            IssuerName = input.ReadString();
            break;
          }
          case 18: {
            IssuerPubkey = input.ReadString();
            break;
          }
        }
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
            break;
          case 10: {
            IssuerName = input.ReadString();
            break;
          }
          case 18: {
            IssuerPubkey = input.ReadString();
            break;
          }
        }
      }
    }
    #endif

  }

  public sealed partial class PublicKeyList : pb::IMessage<PublicKeyList>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<PublicKeyList> _parser = new pb::MessageParser<PublicKeyList>(() => new PublicKeyList());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<PublicKeyList> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::ZkVerifier.ZkVerifierReflection.Descriptor.MessageTypes[1]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public PublicKeyList() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public PublicKeyList(PublicKeyList other) : this() {
      publicKeys_ = other.publicKeys_.Clone();
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public PublicKeyList Clone() {
      return new PublicKeyList(this);
    }

    /// <summary>Field number for the "public_keys" field.</summary>
    public const int PublicKeysFieldNumber = 1;
    private static readonly pb::FieldCodec<string> _repeated_publicKeys_codec
        = pb::FieldCodec.ForString(10);
    private readonly pbc::RepeatedField<string> publicKeys_ = new pbc::RepeatedField<string>();
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pbc::RepeatedField<string> PublicKeys {
      get { return publicKeys_; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as PublicKeyList);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(PublicKeyList other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if(!publicKeys_.Equals(other.publicKeys_)) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      hash ^= publicKeys_.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void WriteTo(pb::CodedOutputStream output) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      output.WriteRawMessage(this);
    #else
      publicKeys_.WriteTo(output, _repeated_publicKeys_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
      publicKeys_.WriteTo(ref output, _repeated_publicKeys_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(ref output);
      }
    }
    #endif

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int CalculateSize() {
      int size = 0;
      size += publicKeys_.CalculateSize(_repeated_publicKeys_codec);
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(PublicKeyList other) {
      if (other == null) {
        return;
      }
      publicKeys_.Add(other.publicKeys_);
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(pb::CodedInputStream input) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      input.ReadRawMessage(this);
    #else
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            publicKeys_.AddEntriesFrom(input, _repeated_publicKeys_codec);
            break;
          }
        }
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
            break;
          case 10: {
            publicKeys_.AddEntriesFrom(ref input, _repeated_publicKeys_codec);
            break;
          }
        }
      }
    }
    #endif

  }

  public sealed partial class IssuerList : pb::IMessage<IssuerList>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<IssuerList> _parser = new pb::MessageParser<IssuerList>(() => new IssuerList());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<IssuerList> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::ZkVerifier.ZkVerifierReflection.Descriptor.MessageTypes[2]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerList() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerList(IssuerList other) : this() {
      issuers_ = other.issuers_.Clone();
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public IssuerList Clone() {
      return new IssuerList(this);
    }

    /// <summary>Field number for the "issuers" field.</summary>
    public const int IssuersFieldNumber = 1;
    private static readonly pb::FieldCodec<string> _repeated_issuers_codec
        = pb::FieldCodec.ForString(10);
    private readonly pbc::RepeatedField<string> issuers_ = new pbc::RepeatedField<string>();
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public pbc::RepeatedField<string> Issuers {
      get { return issuers_; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as IssuerList);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(IssuerList other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if(!issuers_.Equals(other.issuers_)) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      hash ^= issuers_.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void WriteTo(pb::CodedOutputStream output) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      output.WriteRawMessage(this);
    #else
      issuers_.WriteTo(output, _repeated_issuers_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
      issuers_.WriteTo(ref output, _repeated_issuers_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(ref output);
      }
    }
    #endif

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int CalculateSize() {
      int size = 0;
      size += issuers_.CalculateSize(_repeated_issuers_codec);
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(IssuerList other) {
      if (other == null) {
        return;
      }
      issuers_.Add(other.issuers_);
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(pb::CodedInputStream input) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      input.ReadRawMessage(this);
    #else
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            issuers_.AddEntriesFrom(input, _repeated_issuers_codec);
            break;
          }
        }
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
            break;
          case 10: {
            issuers_.AddEntriesFrom(ref input, _repeated_issuers_codec);
            break;
          }
        }
      }
    }
    #endif

  }

  #endregion

}

#endregion Designer generated code