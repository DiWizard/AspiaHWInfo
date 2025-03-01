//
// SPRMatch v.1.2 (11.10.2024)
//

package info.malenkov.aspiahwinfo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.jcajce.provider.digest.Blake2b.Blake2b512;
import org.bouncycastle.jcajce.provider.digest.Blake2s.Blake2s256;
import org.bouncycastle.util.encoders.Hex;

public class SPRMatch{

	public static String bytesToHex(byte[] bytes, boolean... toUpper) {
		final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
		boolean convert2Upper = (toUpper.length >= 1) ? toUpper[0] : false;
        char[] hexChars = new char[bytes.length * 2];

		for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }

		if(convert2Upper) 
    	    return new String(hexChars).toUpperCase();
        else
        	return new String(hexChars);
    }

    static BigInteger RAND(int len, SecureRandom random){
        return org.bouncycastle.util.BigIntegers.createRandomBigInteger(len, random);
    }
    
    static byte[] HS2BA(String data){
        return Hex.decode(data);
    }

	static String BA2HS(byte[] bytes, boolean... toUpper) {
		boolean convert2Upper = (toUpper.length >= 1) ? toUpper[0] : false;

		if(convert2Upper) 
    	    return Hex.toHexString(bytes).toUpperCase();
        else
        	return Hex.toHexString(bytes);
    }

    static byte[] BI2BA(BigInteger value){
        return org.bouncycastle.util.BigIntegers.asUnsignedByteArray(value);
    }

    static byte[] BI2BA(BigInteger value, int minLen){
        return zeroFill(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(value), minLen);
    }

    static BigInteger BA2BI(byte[] data){
        return org.bouncycastle.util.BigIntegers.fromUnsignedByteArray(data);
    }

	// hash = BLAKE2s256(data)
	static BigInteger hash_BLAKE2s256(BigInteger BN_data) throws NoSuchAlgorithmException{
        BigInteger result;

            Blake2s256 blake2s256 = new Blake2s256();
            blake2s256.update(BI2BA(BN_data));
            result = BA2BI(blake2s256.digest());

		return result;
	}

	// hash = BLAKE2b512(data)
    static BigInteger hash_BLAKE2b512(BigInteger BN_data) throws NoSuchAlgorithmException{
        BigInteger result;

        do{
		    Blake2b512 blake2b512 = new Blake2b512();
		    blake2b512.update(BI2BA(BN_data));
            result = BA2BI(blake2b512.digest());
        }while(BI2BA(result).length*8 != 512);
	
		return result;
    }

    // x = BLAKE2b512(s | BLAKE2b512(I | ":" | p))
    static BigInteger calc_x(BigInteger BN_s, String str_I, String str_p) throws NoSuchAlgorithmException{
        Blake2b512 blake2b512 = new Blake2b512();
        
        blake2b512.update(str_I.toLowerCase().getBytes(StandardCharsets.UTF_8), 0, str_I.getBytes(StandardCharsets.UTF_8).length);
        blake2b512.update(":".getBytes(StandardCharsets.UTF_8), 0, ":".getBytes(StandardCharsets.UTF_8).length);
        blake2b512.update(str_p.getBytes(StandardCharsets.UTF_8), 0, str_p.getBytes(StandardCharsets.UTF_8).length);

        Blake2b512 blake2b512bis = new Blake2b512();

		blake2b512bis.update(BI2BA(BN_s));
        blake2b512bis.update(blake2b512.digest());
        
        return BA2BI(blake2b512bis.digest());
    }


    // xy = BLAKE2b512(PAD(x) || PAD(y))
    static BigInteger calc_xy(BigInteger BN_x, BigInteger BN_y, BigInteger BN_N) throws NoSuchAlgorithmException{
		int N_bytes = BI2BA(BN_N).length;
        byte[] xy = new byte[N_bytes + N_bytes];

        Arrays.fill(xy, (byte) 0);
         
        System.arraycopy(BI2BA(BN_x), 0, xy, 0, BI2BA(BN_x).length);
        System.arraycopy(BI2BA(BN_y), 0, xy, N_bytes + N_bytes - BI2BA(BN_y).length, BI2BA(BN_y).length);

		Blake2b512 blake2b512 = new Blake2b512();
		blake2b512.update(xy);

        return BA2BI(blake2b512.digest());
    }

    // calc_u() => calc_xy(A, B, N)
    // u = BLAKE2b512(PAD(A) | PAD(B))
    static BigInteger calc_u(BigInteger BN_A, BigInteger BN_B, BigInteger BN_N) throws NoSuchAlgorithmException{
        return calc_xy(BN_A, BN_B, BN_N);
    }

    // calc_k() => calc_xy(N, g, N)
    // k = BLAKE2b512(N | PAD(g))
    static BigInteger calc_k(BigInteger BN_N, BigInteger BN_g) throws NoSuchAlgorithmException{
        return calc_xy(BN_N, BN_g, BN_N);
    }

    //  calc_A(): 
    //  A = g^a % N
    static BigInteger calc_A(BigInteger BN_a, BigInteger BN_N, BigInteger BN_g) throws NoSuchAlgorithmException{
        BigInteger BN_A;

        BN_A = BN_g.modPow(BN_a, BN_N);

        return BN_A;
    }

    //  calc_B(): 
    //  B = k*v + g^b % N
    static BigInteger calc_B(BigInteger BN_b, BigInteger BN_N, BigInteger BN_g, BigInteger BN_v ) throws NoSuchAlgorithmException{
        BigInteger BN_gb;
        BigInteger BN_k;
        BigInteger BN_kv;
        BigInteger BN_B;

        BN_gb = BN_g.modPow(BN_b, BN_N);
		BN_k = calc_k(BN_N, BN_g);
        BN_kv = (BN_k.multiply(BN_v)).mod(BN_N);
        BN_B = (BN_gb.add(BN_kv)).mod(BN_N);

		return BN_B;
    }

	// calcServerKey
	// S = (A * v^u) ^ b % N
	static BigInteger calcServerKey(BigInteger BN_A, BigInteger BN_v, BigInteger BN_u, BigInteger BN_b, BigInteger BN_N){
		// BN_mod_exp(tmp, v, u, N, ctx)) <--- tmp = (v ^ u) mod N 
		BigInteger tmp = BN_v.modPow(BN_u, BN_N);

		// BN_mod_mul(tmp, A, tmp, N, ctx)) <--- tmp = (A * tmp) mod N
		tmp = BN_A.multiply(tmp).mod(BN_N);

		// BN_mod_exp(S, tmp, b, N, ctx)) <--- S = (tmp ^ b) mod N
		BigInteger BN_S = tmp.modPow(BN_b, BN_N);

		return BN_S;
	}

	// calcClientKey()
	// K = (B - (k * g^x)) ^ (a + (u * x)) % N
	static BigInteger calcClientKey(BigInteger BN_N, BigInteger BN_B, BigInteger BN_g, BigInteger BN_x, BigInteger BN_a, BigInteger BN_u) throws NoSuchAlgorithmException{
		BigInteger BN_k = calc_k(BN_N, BN_g);
		BigInteger tmp = BN_g.modPow(BN_x, BN_N);
		BigInteger tmp2 = tmp.multiply(BN_k).mod(BN_N);
		tmp = BN_B.subtract(tmp2).mod(BN_N);
		BigInteger tmp3 = BN_u.multiply(BN_x);
		tmp2 = BN_a.add(tmp3);
		BigInteger BN_K = tmp.modPow(tmp2, BN_N);
		
		return BN_K;
	}

	static boolean verify_B_mod_N(BigInteger BN_B, BigInteger BN_N){
		return !BN_B.mod(BN_N).equals(0);
	}

	static BigInteger calc_v(String str_I, String str_p, BigInteger BN_s, BigInteger BN_N, BigInteger BN_g) throws NoSuchAlgorithmException{
		BigInteger BN_x = calc_x(BN_s, str_I, str_p);
		return BN_g.modPow(BN_x, BN_N);
	}

    static BigInteger increment(BigInteger integer) {
        return add(integer == null ? BigInteger.ZERO : integer, BigInteger.ONE);
    }

    private static BigInteger add(BigInteger... operands) {
        BigInteger result = null;

        if (operands != null) {
            for (BigInteger operand : operands) {
                if (operand != null) {
                    if (result == null) {
                        result = operand;
                    } else {
                        result = result.add(operand);
                    }
                }
            }
        }

        return result;
    }

    private static byte [] zeroFill(byte[] srcData, int len){
		byte[] prefix = null;
		if(srcData.length < len){
			prefix = new byte[len - srcData.length];
		}
       
		return org.bouncycastle.util.Arrays.concatenate(prefix, srcData);
	}

    public static String randomString(int len){
		final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		SecureRandom rnd = new SecureRandom();

		StringBuilder sb = new StringBuilder(len);
		for(int i = 0; i < len; i++)
		   sb.append(AB.charAt(rnd.nextInt(AB.length())));
		return sb.toString();
	}

}