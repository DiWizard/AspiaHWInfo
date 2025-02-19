// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.common.proto

package info.malenkov.aspiahwinfo.proto;

/**
 * Protobuf enum {@code info.malenkov.aspiahwinfo.proto.SessionType}
 */
public enum SessionType
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>SESSION_TYPE_UNKNOWN = 0;</code>
   */
  SESSION_TYPE_UNKNOWN(0),
  /**
   * <code>SESSION_TYPE_DESKTOP_MANAGE = 1;</code>
   */
  SESSION_TYPE_DESKTOP_MANAGE(1),
  /**
   * <code>SESSION_TYPE_DESKTOP_VIEW = 2;</code>
   */
  SESSION_TYPE_DESKTOP_VIEW(2),
  /**
   * <code>SESSION_TYPE_FILE_TRANSFER = 4;</code>
   */
  SESSION_TYPE_FILE_TRANSFER(4),
  /**
   * <code>SESSION_TYPE_SYSTEM_INFO = 8;</code>
   */
  SESSION_TYPE_SYSTEM_INFO(8),
  /**
   * <code>SESSION_TYPE_TEXT_CHAT = 16;</code>
   */
  SESSION_TYPE_TEXT_CHAT(16),
  /**
   * <pre>
   * When adding or removing session types, you need to recalculate this value.
   * </pre>
   *
   * <code>SESSION_TYPE_ALL = 31;</code>
   */
  SESSION_TYPE_ALL(31),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>SESSION_TYPE_UNKNOWN = 0;</code>
   */
  public static final int SESSION_TYPE_UNKNOWN_VALUE = 0;
  /**
   * <code>SESSION_TYPE_DESKTOP_MANAGE = 1;</code>
   */
  public static final int SESSION_TYPE_DESKTOP_MANAGE_VALUE = 1;
  /**
   * <code>SESSION_TYPE_DESKTOP_VIEW = 2;</code>
   */
  public static final int SESSION_TYPE_DESKTOP_VIEW_VALUE = 2;
  /**
   * <code>SESSION_TYPE_FILE_TRANSFER = 4;</code>
   */
  public static final int SESSION_TYPE_FILE_TRANSFER_VALUE = 4;
  /**
   * <code>SESSION_TYPE_SYSTEM_INFO = 8;</code>
   */
  public static final int SESSION_TYPE_SYSTEM_INFO_VALUE = 8;
  /**
   * <code>SESSION_TYPE_TEXT_CHAT = 16;</code>
   */
  public static final int SESSION_TYPE_TEXT_CHAT_VALUE = 16;
  /**
   * <pre>
   * When adding or removing session types, you need to recalculate this value.
   * </pre>
   *
   * <code>SESSION_TYPE_ALL = 31;</code>
   */
  public static final int SESSION_TYPE_ALL_VALUE = 31;


  public final int getNumber() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalArgumentException(
          "Can't get the number of an unknown enum value.");
    }
    return value;
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   * @deprecated Use {@link #forNumber(int)} instead.
   */
  @java.lang.Deprecated
  public static SessionType valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static SessionType forNumber(int value) {
    switch (value) {
      case 0: return SESSION_TYPE_UNKNOWN;
      case 1: return SESSION_TYPE_DESKTOP_MANAGE;
      case 2: return SESSION_TYPE_DESKTOP_VIEW;
      case 4: return SESSION_TYPE_FILE_TRANSFER;
      case 8: return SESSION_TYPE_SYSTEM_INFO;
      case 16: return SESSION_TYPE_TEXT_CHAT;
      case 31: return SESSION_TYPE_ALL;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<SessionType>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      SessionType> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<SessionType>() {
          public SessionType findValueByNumber(int number) {
            return SessionType.forNumber(number);
          }
        };

  public final com.google.protobuf.Descriptors.EnumValueDescriptor
      getValueDescriptor() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalStateException(
          "Can't get the descriptor of an unrecognized enum value.");
    }
    return getDescriptor().getValues().get(ordinal());
  }
  public final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptorForType() {
    return getDescriptor();
  }
  public static final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptor() {
    return info.malenkov.aspiahwinfo.proto.AspiaCommon.getDescriptor().getEnumTypes().get(0);
  }

  private static final SessionType[] VALUES = values();

  public static SessionType valueOf(
      com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
    if (desc.getType() != getDescriptor()) {
      throw new java.lang.IllegalArgumentException(
        "EnumValueDescriptor is not for this type.");
    }
    if (desc.getIndex() == -1) {
      return UNRECOGNIZED;
    }
    return VALUES[desc.getIndex()];
  }

  private final int value;

  private SessionType(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:info.malenkov.aspiahwinfo.proto.SessionType)
}

