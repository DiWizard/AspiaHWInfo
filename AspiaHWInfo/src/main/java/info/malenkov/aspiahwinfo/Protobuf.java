package info.malenkov.aspiahwinfo;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class Protobuf{
	public static byte[] addSize(byte[] value) {
		byte[] newBuffer = null;

		if (value.length > 0) {
			int var128Size = (int) var128Size(value.length);
			newBuffer = new byte[value.length + var128Size];
			System.arraycopy(var128Encode(value.length), 0, newBuffer, 0, var128Size);
			System.arraycopy(value, 0, newBuffer, var128Size, value.length);
		}

		return newBuffer;
	}

	public static  byte[] skipSize(byte[] value) {
		byte[] newBuffer = null;

		if (value.length > 0) {
			int msgLen = (int) var128Decode(value);
			newBuffer = new byte[msgLen];
			System.arraycopy(value, var128DecodeSize(value), newBuffer, 0, msgLen);
		}

		return newBuffer;
	}

	public static int var128Size(long x) {
		int size = 1;
		while (Long.compareUnsigned(x, 127) > 0) {
			size++;
			x >>>= 7;
		}
		return size;
	}

    public static byte[] var128Encode(long x) {
		ByteBuffer bb = ByteBuffer.wrap(new byte[var128Size(x)]);

		while (Long.compareUnsigned(x, 127) > 0) {
			bb.put((byte) (x & 127 | 128));
			x >>>= 7;
		}
		bb.put((byte) (x & 127));

		return bb.array();
	}

	public static long var128Decode(byte[] buffer) {
		ByteBuffer bb = ByteBuffer.wrap(buffer);
		long x = 0;
		int shift = 0;
		long b;

		do {
			b = bb.get() & 0xff;
			x |= (b & 127) << shift;
			shift += 7;
		} while ((b & 128) != 0);

		return x;
	}

	public static int var128DecodeSize(byte[] buffer) {
		ByteBuffer bb = ByteBuffer.wrap(buffer);
		int bytes = 0;
		long b;

		do {
			b = bb.get() & 0xff;
			bytes ++;
		} while ((b & 128) != 0);

		return bytes;
	}

	public static byte[] read(BufferedInputStream in) throws IOException, InterruptedException{
		int termLength = 0;
		byte[] buffer = new byte[0];
		byte[] term = new byte[65535]; // 16384

		do{		
			termLength = in.read(term, 0, 65535);
			buffer = concatenate(buffer, term, termLength);
			Thread.sleep(100);
		}while(in.available() > 0);

		return buffer;
	}

	public static byte[] concatenate(byte[] first, byte[] second, int length){
		byte[] combined = new byte[first.length + length];
		
		if(first.length > 0){
			System.arraycopy(first,0,combined,0,first.length);
		}
		if(second.length > 0){
			System.arraycopy(second,0,combined,first.length,length);
		}
		
		return combined;
	}
  
}
