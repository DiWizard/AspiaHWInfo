// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.desktop.proto

package info.malenkov.aspiahwinfo.proto;

public interface VideoPacketOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiahwinfo.proto.VideoPacket)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.info.malenkov.aspiahwinfo.proto.VideoEncoding encoding = 1;</code>
   * @return The enum numeric value on the wire for encoding.
   */
  int getEncodingValue();
  /**
   * <code>.info.malenkov.aspiahwinfo.proto.VideoEncoding encoding = 1;</code>
   * @return The encoding.
   */
  info.malenkov.aspiahwinfo.proto.VideoEncoding getEncoding();

  /**
   * <pre>
   * If the screen size or the pixel format has changed, the field must be filled.
   * </pre>
   *
   * <code>.info.malenkov.aspiahwinfo.proto.VideoPacketFormat format = 2;</code>
   * @return Whether the format field is set.
   */
  boolean hasFormat();
  /**
   * <pre>
   * If the screen size or the pixel format has changed, the field must be filled.
   * </pre>
   *
   * <code>.info.malenkov.aspiahwinfo.proto.VideoPacketFormat format = 2;</code>
   * @return The format.
   */
  info.malenkov.aspiahwinfo.proto.VideoPacketFormat getFormat();
  /**
   * <pre>
   * If the screen size or the pixel format has changed, the field must be filled.
   * </pre>
   *
   * <code>.info.malenkov.aspiahwinfo.proto.VideoPacketFormat format = 2;</code>
   */
  info.malenkov.aspiahwinfo.proto.VideoPacketFormatOrBuilder getFormatOrBuilder();

  /**
   * <pre>
   * The list of changed rectangles (areas) of the screen.
   * </pre>
   *
   * <code>repeated .info.malenkov.aspiahwinfo.proto.Rect dirty_rect = 3;</code>
   */
  java.util.List<info.malenkov.aspiahwinfo.proto.Rect> 
      getDirtyRectList();
  /**
   * <pre>
   * The list of changed rectangles (areas) of the screen.
   * </pre>
   *
   * <code>repeated .info.malenkov.aspiahwinfo.proto.Rect dirty_rect = 3;</code>
   */
  info.malenkov.aspiahwinfo.proto.Rect getDirtyRect(int index);
  /**
   * <pre>
   * The list of changed rectangles (areas) of the screen.
   * </pre>
   *
   * <code>repeated .info.malenkov.aspiahwinfo.proto.Rect dirty_rect = 3;</code>
   */
  int getDirtyRectCount();
  /**
   * <pre>
   * The list of changed rectangles (areas) of the screen.
   * </pre>
   *
   * <code>repeated .info.malenkov.aspiahwinfo.proto.Rect dirty_rect = 3;</code>
   */
  java.util.List<? extends info.malenkov.aspiahwinfo.proto.RectOrBuilder> 
      getDirtyRectOrBuilderList();
  /**
   * <pre>
   * The list of changed rectangles (areas) of the screen.
   * </pre>
   *
   * <code>repeated .info.malenkov.aspiahwinfo.proto.Rect dirty_rect = 3;</code>
   */
  info.malenkov.aspiahwinfo.proto.RectOrBuilder getDirtyRectOrBuilder(
      int index);

  /**
   * <pre>
   * Video packet data.
   * </pre>
   *
   * <code>bytes data = 4;</code>
   * @return The data.
   */
  com.google.protobuf.ByteString getData();
}
