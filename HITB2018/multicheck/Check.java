package tmp;

import java.util.Arrays;

public class Check {
    private static int[] a;
    private static byte[] b;

    static {
        Check.a = new int[]{-1414812757, -842150451, -269488145, 305419896};
        Check.b = new byte[]{99, 124, 101, -23, -114, 81, -47, -39, -102, 79, 22, 52, -39, -94, -66, -72, 101, -18, 73, -27, 53, -5, 46, -20, 97, 11, -56, 36, -19, -49, -112, -75};
    }

    public Check() {
        super();
    }

    private static int a(byte arg0) {
        int v0=arg0;
        if(arg0 < 0) {
            v0 = arg0 + 256;
        }

        return v0;
    }

    public static byte[] a(byte[] arg6) {
        int v0 = 8 - arg6.length % 8;
        byte[] v2 = new byte[arg6.length + v0];
        v2[0] = ((byte)v0);
        System.arraycopy(arg6, 0, v2, v0, arg6.length);
        byte[] v3 = new byte[v2.length];
        for(v0 = 0; v0 < v3.length; v0 += 8) {
            System.arraycopy(Check.a(v2, v0, Check.a, 32), 0, v3, v0, 8);
        }

        return v3;
    }
    

    static byte[] a(byte[] arg12, int arg13, int[] arg14, int arg15) {
        int[] v4 = Check.a(arg12, arg13);
        int v3 = v4[0];
        int v2 = v4[1];
        int v1 = 0;
        int v5 = -1640531527;
        int v6 = arg14[0];
        int v7 = arg14[1];
        int v8 = arg14[2];
        int v9 = arg14[3];
        int v0;
        for(v0 = 0; v0 < arg15; ++v0) {
            v1 += v5;
            v3 += (v2 << 4) + v6 ^ v2 + v1 ^ (v2 >> 5) + v7;
            v2 += (v3 << 4) + v8 ^ v3 + v1 ^ (v3 >> 5) + v9;
        }

        v4[0] = v3;
        v4[1] = v2;
        return Check.a(v4, 0);
    }
    
    static byte[] dea(byte[] arg12, int arg13, int[] arg14, int arg15) {
        int[] v4 = Check.a(arg12, arg13);
        int v3 = v4[0];
        int v2 = v4[1];
        int v1 = 0;
        int v5 = -1640531527;
        int v6 = arg14[0];
        int v7 = arg14[1];
        int v8 = arg14[2];
        int v9 = arg14[3];
        int v0;
        for(int i=0;i<arg15;i++)
        	v1+=v5;
        for(v0 = 0; v0 < arg15; ++v0) {
        	v2 -= (v3 << 4) + v8 ^ v3 + v1 ^ (v3 >> 5) + v9;
        	v3 -= (v2 << 4) + v6 ^ v2 + v1 ^ (v2 >> 5) + v7;
            v1 -= v5;
        }

        v4[0] = v3;
        v4[1] = v2;
        return Check.a(v4, 0);
    } 

    private static int[] a(byte[] arg4, int arg5) {
        int[] v1 = new int[arg4.length >> 2];
        int v0 = 0;
        while(arg5 < arg4.length) {
            v1[v0] = Check.a(arg4[arg5 + 3]) | Check.a(arg4[arg5 + 2]) << 8 | Check.a(arg4[arg5 + 1]) << 16 | arg4[arg5] << 24;
            ++v0;
            arg5 += 4;
        }

        return v1;
    }

    private static byte[] a(int[] arg4, int arg5) {
        byte[] v1 = new byte[arg4.length << 2];
        int v0 = 0;
        while(arg5 < v1.length) {
            v1[arg5 + 3] = ((byte)(arg4[v0] & 255));
            v1[arg5 + 2] = ((byte)(arg4[v0] >> 8 & 255));
            v1[arg5 + 1] = ((byte)(arg4[v0] >> 16 & 255));
            v1[arg5] = ((byte)(arg4[v0] >> 24 & 255));
            ++v0;
            arg5 += 4;
        }

        return v1;
    }

    public static boolean check(String arg2) {
    	byte[] tmp=Check.a(arg2.getBytes());
    	for(int i=0;i<tmp.length;i++)
    	{
    		System.out.print(tmp[i]+" ");
    	}
    	System.out.println("");
    	System.out.println(Check.a(arg2.getBytes()));
    	System.out.println(Check.b);
        return Arrays.equals(Check.a(arg2.getBytes()), Check.b);
    }
    
    public static void main(String args[])
    {
    	byte tmp[]=Check.a("aa".getBytes());
    	for(int q=0;q<=24;q+=8)
    	{
        	byte[] detmp=Check.dea(Check.b, q,Check.a,32);
        	for(int i=0;i<8;i++)
        	{
        		System.out.print(detmp[i]+" ,");
        	}
    	}
    	System.out.println("");
    }
}

