// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key_exchange.proto

package info.malenkov.aspiahwinfo.proto;

/**
 * <pre>
 * Client to server.
 * </pre>
 *
 * Protobuf type {@code info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange}
 */
public final class SrpClientKeyExchange extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)
    SrpClientKeyExchangeOrBuilder {
private static final long serialVersionUID = 0L;
  // Use SrpClientKeyExchange.newBuilder() to construct.
  private SrpClientKeyExchange(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private SrpClientKeyExchange() {
    a_ = com.google.protobuf.ByteString.EMPTY;
    iv_ = com.google.protobuf.ByteString.EMPTY;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new SrpClientKeyExchange();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private SrpClientKeyExchange(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 10: {

            a_ = input.readBytes();
            break;
          }
          case 18: {

            iv_ = input.readBytes();
            break;
          }
          default: {
            if (!parseUnknownField(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (com.google.protobuf.UninitializedMessageException e) {
      throw e.asInvalidProtocolBufferException().setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return info.malenkov.aspiahwinfo.proto.AspiaKeyExchange.internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return info.malenkov.aspiahwinfo.proto.AspiaKeyExchange.internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.class, info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.Builder.class);
  }

  public static final int A_FIELD_NUMBER = 1;
  private com.google.protobuf.ByteString a_;
  /**
   * <code>bytes A = 1;</code>
   * @return The a.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getA() {
    return a_;
  }

  public static final int IV_FIELD_NUMBER = 2;
  private com.google.protobuf.ByteString iv_;
  /**
   * <code>bytes iv = 2;</code>
   * @return The iv.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getIv() {
    return iv_;
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (!a_.isEmpty()) {
      output.writeBytes(1, a_);
    }
    if (!iv_.isEmpty()) {
      output.writeBytes(2, iv_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!a_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(1, a_);
    }
    if (!iv_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(2, iv_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)) {
      return super.equals(obj);
    }
    info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange other = (info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange) obj;

    if (!getA()
        .equals(other.getA())) return false;
    if (!getIv()
        .equals(other.getIv())) return false;
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + A_FIELD_NUMBER;
    hash = (53 * hash) + getA().hashCode();
    hash = (37 * hash) + IV_FIELD_NUMBER;
    hash = (53 * hash) + getIv().hashCode();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * <pre>
   * Client to server.
   * </pre>
   *
   * Protobuf type {@code info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)
      info.malenkov.aspiahwinfo.proto.SrpClientKeyExchangeOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return info.malenkov.aspiahwinfo.proto.AspiaKeyExchange.internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return info.malenkov.aspiahwinfo.proto.AspiaKeyExchange.internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.class, info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.Builder.class);
    }

    // Construct using info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      a_ = com.google.protobuf.ByteString.EMPTY;

      iv_ = com.google.protobuf.ByteString.EMPTY;

      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return info.malenkov.aspiahwinfo.proto.AspiaKeyExchange.internal_static_info_malenkov_aspiahwinfo_proto_SrpClientKeyExchange_descriptor;
    }

    @java.lang.Override
    public info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange getDefaultInstanceForType() {
      return info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.getDefaultInstance();
    }

    @java.lang.Override
    public info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange build() {
      info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange buildPartial() {
      info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange result = new info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange(this);
      result.a_ = a_;
      result.iv_ = iv_;
      onBuilt();
      return result;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange) {
        return mergeFrom((info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange other) {
      if (other == info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange.getDefaultInstance()) return this;
      if (other.getA() != com.google.protobuf.ByteString.EMPTY) {
        setA(other.getA());
      }
      if (other.getIv() != com.google.protobuf.ByteString.EMPTY) {
        setIv(other.getIv());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private com.google.protobuf.ByteString a_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>bytes A = 1;</code>
     * @return The a.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getA() {
      return a_;
    }
    /**
     * <code>bytes A = 1;</code>
     * @param value The a to set.
     * @return This builder for chaining.
     */
    public Builder setA(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      a_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>bytes A = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearA() {
      
      a_ = getDefaultInstance().getA();
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString iv_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>bytes iv = 2;</code>
     * @return The iv.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getIv() {
      return iv_;
    }
    /**
     * <code>bytes iv = 2;</code>
     * @param value The iv to set.
     * @return This builder for chaining.
     */
    public Builder setIv(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      iv_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>bytes iv = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearIv() {
      
      iv_ = getDefaultInstance().getIv();
      onChanged();
      return this;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)
  }

  // @@protoc_insertion_point(class_scope:info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange)
  private static final info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange();
  }

  public static info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<SrpClientKeyExchange>
      PARSER = new com.google.protobuf.AbstractParser<SrpClientKeyExchange>() {
    @java.lang.Override
    public SrpClientKeyExchange parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new SrpClientKeyExchange(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<SrpClientKeyExchange> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<SrpClientKeyExchange> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

