// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.desktop.proto

package info.malenkov.aspiahwinfo.proto;

/**
 * Protobuf enum {@code info.malenkov.aspiahwinfo.proto.AudioEncoding}
 */
public enum AudioEncoding
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>AUDIO_ENCODING_UNKNOWN = 0;</code>
   */
  AUDIO_ENCODING_UNKNOWN(0),
  /**
   * <code>AUDIO_ENCODING_DEFAULT = 1;</code>
   */
  AUDIO_ENCODING_DEFAULT(1),
  /**
   * <code>AUDIO_ENCODING_RAW = 2;</code>
   */
  AUDIO_ENCODING_RAW(2),
  /**
   * <code>AUDIO_ENCODING_OPUS = 3;</code>
   */
  AUDIO_ENCODING_OPUS(3),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>AUDIO_ENCODING_UNKNOWN = 0;</code>
   */
  public static final int AUDIO_ENCODING_UNKNOWN_VALUE = 0;
  /**
   * <code>AUDIO_ENCODING_DEFAULT = 1;</code>
   */
  public static final int AUDIO_ENCODING_DEFAULT_VALUE = 1;
  /**
   * <code>AUDIO_ENCODING_RAW = 2;</code>
   */
  public static final int AUDIO_ENCODING_RAW_VALUE = 2;
  /**
   * <code>AUDIO_ENCODING_OPUS = 3;</code>
   */
  public static final int AUDIO_ENCODING_OPUS_VALUE = 3;


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
  public static AudioEncoding valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static AudioEncoding forNumber(int value) {
    switch (value) {
      case 0: return AUDIO_ENCODING_UNKNOWN;
      case 1: return AUDIO_ENCODING_DEFAULT;
      case 2: return AUDIO_ENCODING_RAW;
      case 3: return AUDIO_ENCODING_OPUS;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<AudioEncoding>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      AudioEncoding> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<AudioEncoding>() {
          public AudioEncoding findValueByNumber(int number) {
            return AudioEncoding.forNumber(number);
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
    return info.malenkov.aspiahwinfo.proto.AspiaDesktop.getDescriptor().getEnumTypes().get(1);
  }

  private static final AudioEncoding[] VALUES = values();

  public static AudioEncoding valueOf(
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

  private AudioEncoding(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:info.malenkov.aspiahwinfo.proto.AudioEncoding)
}

