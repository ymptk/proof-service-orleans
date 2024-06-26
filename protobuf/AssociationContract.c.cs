// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: association_contract.proto
// </auto-generated>
#pragma warning disable 0414, 1591
#region Designer generated code

using System.Collections.Generic;
using aelf = global::AElf.CSharp.Core;

namespace AElf.Contracts.Association {

  #region Events
  internal partial class MemberAdded : aelf::IEvent<MemberAdded>
  {
    public global::System.Collections.Generic.IEnumerable<MemberAdded> GetIndexed()
    {
      return new List<MemberAdded>
      {
      new MemberAdded
      {
        OrganizationAddress = OrganizationAddress
      },
      };
    }

    public MemberAdded GetNonIndexed()
    {
      return new MemberAdded
      {
        Member = Member,
      };
    }
  }

  internal partial class MemberRemoved : aelf::IEvent<MemberRemoved>
  {
    public global::System.Collections.Generic.IEnumerable<MemberRemoved> GetIndexed()
    {
      return new List<MemberRemoved>
      {
      new MemberRemoved
      {
        OrganizationAddress = OrganizationAddress
      },
      };
    }

    public MemberRemoved GetNonIndexed()
    {
      return new MemberRemoved
      {
        Member = Member,
      };
    }
  }

  internal partial class MemberChanged : aelf::IEvent<MemberChanged>
  {
    public global::System.Collections.Generic.IEnumerable<MemberChanged> GetIndexed()
    {
      return new List<MemberChanged>
      {
      new MemberChanged
      {
        OrganizationAddress = OrganizationAddress
      },
      };
    }

    public MemberChanged GetNonIndexed()
    {
      return new MemberChanged
      {
        OldMember = OldMember,
        NewMember = NewMember,
      };
    }
  }

  #endregion
  internal static partial class AssociationContractContainer
  {
    static readonly string __ServiceName = "Association.AssociationContract";

    #region Marshallers
    static readonly aelf::Marshaller<global::AElf.Contracts.Association.CreateOrganizationInput> __Marshaller_Association_CreateOrganizationInput = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::AElf.Contracts.Association.CreateOrganizationInput.Parser.ParseFrom);
    static readonly aelf::Marshaller<global::AElf.Types.Address> __Marshaller_aelf_Address = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::AElf.Types.Address.Parser.ParseFrom);
    static readonly aelf::Marshaller<global::AElf.Contracts.Association.CreateOrganizationBySystemContractInput> __Marshaller_Association_CreateOrganizationBySystemContractInput = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::AElf.Contracts.Association.CreateOrganizationBySystemContractInput.Parser.ParseFrom);
    static readonly aelf::Marshaller<global::Google.Protobuf.WellKnownTypes.Empty> __Marshaller_google_protobuf_Empty = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::Google.Protobuf.WellKnownTypes.Empty.Parser.ParseFrom);
    static readonly aelf::Marshaller<global::AElf.Contracts.Association.ChangeMemberInput> __Marshaller_Association_ChangeMemberInput = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::AElf.Contracts.Association.ChangeMemberInput.Parser.ParseFrom);
    static readonly aelf::Marshaller<global::AElf.Contracts.Association.Organization> __Marshaller_Association_Organization = aelf::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::AElf.Contracts.Association.Organization.Parser.ParseFrom);
    #endregion

    #region Methods
    static readonly aelf::Method<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address> __Method_CreateOrganization = new aelf::Method<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address>(
        aelf::MethodType.Action,
        __ServiceName,
        "CreateOrganization",
        __Marshaller_Association_CreateOrganizationInput,
        __Marshaller_aelf_Address);

    static readonly aelf::Method<global::AElf.Contracts.Association.CreateOrganizationBySystemContractInput, global::AElf.Types.Address> __Method_CreateOrganizationBySystemContract = new aelf::Method<global::AElf.Contracts.Association.CreateOrganizationBySystemContractInput, global::AElf.Types.Address>(
        aelf::MethodType.Action,
        __ServiceName,
        "CreateOrganizationBySystemContract",
        __Marshaller_Association_CreateOrganizationBySystemContractInput,
        __Marshaller_aelf_Address);

    static readonly aelf::Method<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty> __Method_AddMember = new aelf::Method<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty>(
        aelf::MethodType.Action,
        __ServiceName,
        "AddMember",
        __Marshaller_aelf_Address,
        __Marshaller_google_protobuf_Empty);

    static readonly aelf::Method<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty> __Method_RemoveMember = new aelf::Method<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty>(
        aelf::MethodType.Action,
        __ServiceName,
        "RemoveMember",
        __Marshaller_aelf_Address,
        __Marshaller_google_protobuf_Empty);

    static readonly aelf::Method<global::AElf.Contracts.Association.ChangeMemberInput, global::Google.Protobuf.WellKnownTypes.Empty> __Method_ChangeMember = new aelf::Method<global::AElf.Contracts.Association.ChangeMemberInput, global::Google.Protobuf.WellKnownTypes.Empty>(
        aelf::MethodType.Action,
        __ServiceName,
        "ChangeMember",
        __Marshaller_Association_ChangeMemberInput,
        __Marshaller_google_protobuf_Empty);

    static readonly aelf::Method<global::AElf.Types.Address, global::AElf.Contracts.Association.Organization> __Method_GetOrganization = new aelf::Method<global::AElf.Types.Address, global::AElf.Contracts.Association.Organization>(
        aelf::MethodType.View,
        __ServiceName,
        "GetOrganization",
        __Marshaller_aelf_Address,
        __Marshaller_Association_Organization);

    static readonly aelf::Method<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address> __Method_CalculateOrganizationAddress = new aelf::Method<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address>(
        aelf::MethodType.View,
        __ServiceName,
        "CalculateOrganizationAddress",
        __Marshaller_Association_CreateOrganizationInput,
        __Marshaller_aelf_Address);

    #endregion

    #region Descriptors
    public static global::Google.Protobuf.Reflection.ServiceDescriptor Descriptor
    {
      get { return global::AElf.Contracts.Association.AssociationContractReflection.Descriptor.Services[0]; }
    }

    public static global::System.Collections.Generic.IReadOnlyList<global::Google.Protobuf.Reflection.ServiceDescriptor> Descriptors
    {
      get
      {
        return new global::System.Collections.Generic.List<global::Google.Protobuf.Reflection.ServiceDescriptor>()
        {
          global::AElf.Contracts.Association.AssociationContractReflection.Descriptor.Services[0],
        };
      }
    }
    #endregion

    public class AssociationContractReferenceState : global::AElf.Sdk.CSharp.State.ContractReferenceState
    {
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address> CreateOrganization { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Contracts.Association.CreateOrganizationBySystemContractInput, global::AElf.Types.Address> CreateOrganizationBySystemContract { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty> AddMember { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Types.Address, global::Google.Protobuf.WellKnownTypes.Empty> RemoveMember { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Contracts.Association.ChangeMemberInput, global::Google.Protobuf.WellKnownTypes.Empty> ChangeMember { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Types.Address, global::AElf.Contracts.Association.Organization> GetOrganization { get; set; }
      internal global::AElf.Sdk.CSharp.State.MethodReference<global::AElf.Contracts.Association.CreateOrganizationInput, global::AElf.Types.Address> CalculateOrganizationAddress { get; set; }
    }
  }
}
#endregion

