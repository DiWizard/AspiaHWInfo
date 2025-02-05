// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.desktop.proto

package info.malenkov.aspiahwinfo.proto;

/**
 * <pre>
 * Identifies how the image was encoded.
 * </pre>
 *
 * Protobuf enum {@code info.malenkov.aspiahwinfo.proto.VideoEncoding}
 */
public enum VideoEncoding
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>VIDEO_ENCODING_UNKNOWN = 0;</code>
   */
  VIDEO_ENCODING_UNKNOWN(0),
  /**
   * <code>VIDEO_ENCODING_ZSTD = 1;</code>
   */
  VIDEO_ENCODING_ZSTD(1),
  /**
   * <code>VIDEO_ENCODING_VP8 = 2;</code>
   */
  VIDEO_ENCODING_VP8(2),
  /**
   * <code>VIDEO_ENCODING_VP9 = 4;</code>
   */
  VIDEO_ENCODING_VP9(4),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>VIDEO_ENCODING_UNKNOWN = 0;</code>
   */
  public static final int VIDEO_ENCODING_UNKNOWN_VALUE = 0;
  /**
   * <code>VIDEO_ENCODING_ZSTD = 1;</code>
   */
  public static final int VIDEO_ENCODING_ZSTD_VALUE = 1;
  /**
   * <code>VIDEO_ENCODING_VP8 = 2;</code>
   */
  public static final int VIDEO_ENCODING_VP8_VALUE = 2;
  /**
   * <code>VIDEO_ENCODING_VP9 = 4;</code>
   */
  public static final int VIDEO_ENCODING_VP9_VALUE = 4;


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
  public static VideoEncoding valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static VideoEncoding forNumber(int value) {
    switch (value) {
      case 0: return VIDEO_ENCODING_UNKNOWN;
      case 1: return VIDEO_ENCODING_ZSTD;
      case 2: return VIDEO_ENCODING_VP8;
      case 4: return VIDEO_ENCODING_VP9;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<VideoEncoding>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      VideoEncoding> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<VideoEncoding>() {
          public VideoEncoding findValueByNumber(int number) {
            return VideoEncoding.forNumber(number);
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
    return info.malenkov.aspiahwinfo.proto.AspiaDesktop.getDescriptor().getEnumTypes().get(0);
  }

  private static final VideoEncoding[] VALUES = values();

  public static VideoEncoding valueOf(
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

  private VideoEncoding(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:info.malenkov.aspiahwinfo.proto.VideoEncoding)
}

