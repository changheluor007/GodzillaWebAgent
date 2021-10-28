package com.security;

import java.lang.reflect.Method;
import java.util.Arrays;

public class functions {
    public  static final char[] toBase64 = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    public static Method getMethodByClass(Class cs, String methodName, Class[] parameters){
        Method method=null;
        while (cs!=null){
            try {
                method=cs.getDeclaredMethod(methodName, parameters);
                method.setAccessible(true);
                cs=null;
            }catch (Exception e){
                cs=cs.getSuperclass();
            }
        }
        return method;
    }
    public static Object invokeMethod(Object obj,Method method,Object... parameters){
        try {
            return method.invoke(obj, parameters);
        }catch (Exception e){
            return null;
        }
    }
    public static String md5(String s) {
        String ret = null;

        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret=byteArrayToHex(m.digest());
        } catch (Exception e) {
        }
        return ret;
    }
    public static String byteArrayToHex(byte[] bytes) {
        String strHex = "";
        StringBuilder sb = new StringBuilder("");
        for (int n = 0; n < bytes.length; n++) {
            strHex = Integer.toHexString(bytes[n] & 0xFF);
            sb.append((strHex.length() == 1) ? "0" + strHex : strHex); // 每个字节由两个字符表示，位数不够，高位补0
        }
        return sb.toString().trim();
    }
    public static String base64Encode(String data) {
        return base64Encode(data.getBytes());
    }
    public static String base64Encode(byte[] src) {
        int off=0;
        int end=src.length;
        byte[] dst=new byte[4 * ((src.length + 2) / 3)];
        int linemax=-1;
        boolean doPadding=true;
        char[] base64 =toBase64;
        int sp = off;
        int slen = (end - off) / 3 * 3;
        int sl = off + slen;
        if (linemax > 0 && slen  > linemax / 4 * 3) {
            slen = linemax / 4 * 3;
        }
        int dp = 0;
        while (sp < sl) {
            int sl0 = Math.min(sp + slen, sl);
            for (int sp0 = sp, dp0 = dp ; sp0 < sl0; ) {
                int bits = (src[sp0++] & 0xff) << 16 |
                        (src[sp0++] & 0xff) <<  8 |
                        (src[sp0++] & 0xff);
                dst[dp0++] = (byte)base64[(bits >>> 18) & 0x3f];
                dst[dp0++] = (byte)base64[(bits >>> 12) & 0x3f];
                dst[dp0++] = (byte)base64[(bits >>> 6)  & 0x3f];
                dst[dp0++] = (byte)base64[bits & 0x3f];
            }
            int dlen = (sl0 - sp) / 3 * 4;
            dp += dlen;
            sp = sl0;
        }
        if (sp < end) {               // 1 or 2 leftover bytes
            int b0 = src[sp++] & 0xff;
            dst[dp++] = (byte)base64[b0 >> 2];
            if (sp == end) {
                dst[dp++] = (byte)base64[(b0 << 4) & 0x3f];
                if (doPadding) {
                    dst[dp++] = '=';
                    dst[dp++] = '=';
                }
            } else {
                int b1 = src[sp++] & 0xff;
                dst[dp++] = (byte)base64[(b0 << 4) & 0x3f | (b1 >> 4)];
                dst[dp++] = (byte)base64[(b1 << 2) & 0x3f];
                if (doPadding) {
                    dst[dp++] = '=';
                }
            }
        }
        return new String(dst);
    }

    public static byte[] base64Decode(String base64Str) {
        if (base64Str.length()==0) {
            return new byte[] {};
        }
        byte[] src=base64Str.getBytes();
        int sp=0;
        int sl=src.length;
        int paddings = 0;
        int len = sl - sp;
        if (src[sl - 1] == '=') {
            paddings++;
            if (src[sl - 2] == '=') {
                paddings++;
            }
        }
        if (paddings == 0 && (len & 0x3) !=  0) {
            paddings = 4 - (len & 0x3);
        }
        byte[] dst=new byte[3 * ((len + 3) / 4) - paddings];
        int[] base64 = new int[256];
        Arrays.fill(base64, -1);
        for (int i = 0; i < toBase64.length; i++) {
            base64[toBase64[i]] = i;
        }
        base64['='] = -2;
        int dp = 0;
        int bits = 0;
        int shiftto = 18;
        while (sp < sl) {
            int b = src[sp++] & 0xff;
            if ((b = base64[b]) < 0) {
                if (b == -2) {
                    if (shiftto == 6 && (sp == sl || src[sp++] != '=') ||
                            shiftto == 18) {
                        throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
                    }
                    break;
                }
            }
            bits |= (b << shiftto);
            shiftto -= 6;
            if (shiftto < 0) {
                dst[dp++] = (byte)(bits >> 16);
                dst[dp++] = (byte)(bits >>  8);
                dst[dp++] = (byte)(bits);
                shiftto = 18;
                bits = 0;
            }
        }
        // reached end of byte array or hit padding '=' characters.
        if (shiftto == 6) {
            dst[dp++] = (byte)(bits >> 16);
        } else if (shiftto == 0) {
            dst[dp++] = (byte)(bits >> 16);
            dst[dp++] = (byte)(bits >>  8);
        } else if (shiftto == 12) {
            // dangling single "x", incorrectly encoded.
            throw new IllegalArgumentException(
                    "Last unit does not have enough valid bits");
        }
        if (dp != dst.length) {
            byte[] arrayOfByte = new byte[dp];
            System.arraycopy(dst, 0, arrayOfByte, 0, Math.min(dst.length, dp));
            dst = arrayOfByte;
        }
        return dst;
    }
}
