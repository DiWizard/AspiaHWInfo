// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key_exchange.proto

package info.malenkov.aspiahwinfo.proto;

public final class AspiaKeyExchange {
  private AspiaKeyExchange() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_ClientHello_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_ClientHello_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_ServerHello_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_ServerHello_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_SrpIdentify_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_SrpIdentify_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_SrpServerKeyExchange_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_SrpServerKeyExchange_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_SessionChallenge_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_SessionChallenge_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiahwinfo_proto_SessionResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiahwinfo_proto_SessionResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\030aspia.key_exchange.proto\022\037info.malenko" +
      "v.aspiahwinfo.proto\032\022aspia.common.proto\"" +
      "~\n\013ClientHello\022\022\n\nencryption\030\001 \001(\r\022;\n\010id" +
      "entify\030\002 \001(\0162).info.malenkov.aspiahwinfo" +
      ".proto.Identify\022\022\n\npublic_key\030\003 \001(\014\022\n\n\002i" +
      "v\030\004 \001(\014\"Z\n\013ServerHello\022?\n\nencryption\030\001 \001" +
      "(\0162+.info.malenkov.aspiahwinfo.proto.Enc" +
      "ryption\022\n\n\002iv\030\002 \001(\014\"\037\n\013SrpIdentify\022\020\n\010us" +
      "ername\030\001 \001(\t\"^\n\024SrpServerKeyExchange\022\016\n\006" +
      "number\030\001 \001(\014\022\021\n\tgenerator\030\002 \001(\014\022\014\n\004salt\030" +
      "\003 \001(\014\022\t\n\001B\030\004 \001(\014\022\n\n\002iv\030\005 \001(\014\"-\n\024SrpClien" +
      "tKeyExchange\022\t\n\001A\030\001 \001(\014\022\n\n\002iv\030\002 \001(\014\"\237\001\n\020" +
      "SessionChallenge\0229\n\007version\030\001 \001(\0132(.info" +
      ".malenkov.aspiahwinfo.proto.Version\022\025\n\rs" +
      "ession_types\030\002 \001(\r\022\021\n\tcpu_cores\030\003 \001(\r\022\017\n" +
      "\007os_name\030\004 \001(\t\022\025\n\rcomputer_name\030\005 \001(\t\"\235\001" +
      "\n\017SessionResponse\0229\n\007version\030\001 \001(\0132(.inf" +
      "o.malenkov.aspiahwinfo.proto.Version\022\024\n\014" +
      "session_type\030\002 \001(\r\022\021\n\tcpu_cores\030\003 \001(\r\022\017\n" +
      "\007os_name\030\004 \001(\t\022\025\n\rcomputer_name\030\005 \001(\t*4\n" +
      "\010Identify\022\020\n\014IDENTIFY_SRP\020\000\022\026\n\022IDENTIFY_" +
      "ANONYMOUS\020\001*a\n\nEncryption\022\026\n\022ENCRYPTION_" +
      "UNKNOWN\020\000\022 \n\034ENCRYPTION_CHACHA20_POLY130" +
      "5\020\001\022\031\n\025ENCRYPTION_AES256_GCM\020\002B\002P\001b\006prot" +
      "o3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          info.malenkov.aspiahwinfo.proto.AspiaCommon.getDescriptor(),
        });
    internal_static_info_malenkov_aspiahwinfo_proto_ClientHello_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_info_malenkov_aspiahwinfo_proto_ClientHello_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_ClientHello_descriptor,
        new java.lang.String[] { "Encryption", "Identify", "PublicKey", "Iv", });
    internal_static_info_malenkov_aspiahwinfo_proto_ServerHello_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_info_malenkov_aspiahwinfo_proto_ServerHello_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_ServerHello_descriptor,
        new java.lang.String[] { "Encryption", "Iv", });
    internal_static_info_malenkov_aspiahwinfo_proto_SrpIdentify_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_info_malenkov_aspiahwinfo_proto_SrpIdentify_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_SrpIdentify_descriptor,
        new java.lang.String[] { "Username", });
    internal_static_info_malenkov_aspiahwinfo_proto_SrpServerKeyExchange_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_info_malenkov_aspiahwinfo_proto_SrpServerKeyExchange_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_SrpServerKeyExchange_descriptor,
        new java.lang.String[] { "Number", "Generator", "Salt", "B", "Iv", });
    internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor,
        new java.lang.String[] { "A", "Iv", });
    internal_static_info_malenkov_aspiahwinfo_proto_SessionChallenge_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_info_malenkov_aspiahwinfo_proto_SessionChallenge_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_SessionChallenge_descriptor,
        new java.lang.String[] { "Version", "SessionTypes", "CpuCores", "OsName", "ComputerName", });
    internal_static_info_malenkov_aspiahwinfo_proto_SessionResponse_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_info_malenkov_aspiahwinfo_proto_SessionResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiahwinfo_proto_SessionResponse_descriptor,
        new java.lang.String[] { "Version", "SessionType", "CpuCores", "OsName", "ComputerName", });
    info.malenkov.aspiahwinfo.proto.AspiaCommon.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
