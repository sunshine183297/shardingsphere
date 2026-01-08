/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.encrypt.sm.algorithm.fpe;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.shardingsphere.encrypt.sm.algorithm.fpe.util.AES;
import org.apache.shardingsphere.encrypt.sm.algorithm.fpe.util.KeyUtil;
import org.apache.shardingsphere.encrypt.sm.algorithm.fpe.util.Padding;
import org.apache.shardingsphere.encrypt.sm.algorithm.fpe.util.SM4;
import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.jcajce.spec.FPEParameterSpec;

public class FPEForSM4 {
    
    private final AES aes;
    private final SM4 sm4;
    private final AlphabetMapper mapper;
    private static final double TWO_TO_96 = Math.pow((double) 2.0F, (double) 96.0F);
    private int sortCode;
    private String numberMapperStr;
    
    public FPEForSM4(FPEMode mode, byte[] key, AlphabetMapper mapper) {
        this(mode, key, mapper, (byte[]) null);
    }
    
    public FPEForSM4(FPEMode mode, byte[] key, AlphabetMapper mapper, byte[] tweak) {
        this.sortCode = 0;
        if (null == mode) {
            mode = FPEForSM4.FPEMode.FF1;
        }
        
        if (null == tweak) {
            switch (mode) {
                case FF1:
                    tweak = new byte[0];
                    break;
                case FF3_1:
                    tweak = new byte[7];
            }
        }
        
        this.aes = new AES(mode.value, Padding.NoPadding.name(), KeyUtil.generateKey(mode.value, key), new FPEParameterSpec(mapper.getRadix(), tweak));
        this.sm4 = new SM4(mode.value, Padding.NoPadding.name(), KeyUtil.generateKey(mode.value, key), new FPEParameterSpec(mapper.getRadix(), tweak));
        this.mapper = mapper;
    }
    
    public FPEForSM4(FPEMode mode, byte[] key, AlphabetMapper mapper, byte[] tweak, String numberMapperStr) {
        this.sortCode = 0;
        if (null == mode) {
            mode = FPEForSM4.FPEMode.FF1;
        }
        
        if (null == tweak) {
            switch (mode) {
                case FF1:
                    tweak = new byte[0];
                    break;
                case FF3_1:
                    tweak = new byte[7];
            }
        }
        
        this.aes = new AES(mode.value, Padding.NoPadding.name(), KeyUtil.generateKey(mode.value, key), new FPEParameterSpec(mapper.getRadix(), tweak));
        this.sm4 = new SM4(mode.value, Padding.NoPadding.name(), KeyUtil.generateKey(mode.value, key), new FPEParameterSpec(mapper.getRadix(), tweak));
        this.mapper = mapper;
        String keyStr = new String(key);
        this.sortCode = this.calculateSourCode(keyStr);
        this.numberMapperStr = numberMapperStr;
    }
    
    private int calculateSourCode(String key) {
        int i = 0;
        char[] chars = key.toCharArray();
        
        for (char aChar : chars) {
            if (Character.isDigit(aChar)) {
                i += aChar;
            } else {
                i += this.letter2num(aChar);
            }
        }
        
        return i;
    }
    
    private int letter2num(char character) {
        return character - 96 > 0 ? character - 96 : character - 64;
    }
    
    /**
     * Encrypt (Atomic + Fail-Open):
     * - success: return cipher
     * - failure / non-deterministic / partial: return original plain
     */
    public String encrypt(String data) {
        if (data == null) {
            return null;
        }
        return encryptAtomically(data);
    }
    
    /**
     * Decrypt (Fail-Open):
     * - try decrypt; if not a valid cipher (or partial), return original input
     */
    public String decrypt(String data) {
        if (data == null) {
            return null;
        }
        return decryptAtomically(data);
    }
    
    /**
     * Encrypt char[] (used internally by chunk-path).
     * NOTE: This method must be deterministic for valid plaintext input.
     */
    public char[] encrypt(char[] data) {
        return data == null ? null : this.mapper.convertToChars(this.sm4.encrypt(this.mapper.convertToIndexes(data)));
    }
    
    /**
     * Decrypt char[] with validation (Fail-Open).
     * If input is not a valid cipher text, return original char[] to avoid corruption.
     */
    public char[] decrypt(char[] data) {
        if (data == null) {
            return null;
        }
        try {
            char[] decrypted = this.mapper.convertToChars(this.sm4.decrypt(this.mapper.convertToIndexes(data)));
            
            // Validate: encrypt(decrypted) should equal original cipher
            char[] reEncrypted = this.mapper.convertToChars(this.sm4.encrypt(this.mapper.convertToIndexes(decrypted)));
            if (!Arrays.equals(data, reEncrypted)) {
                return data; // Fail-Open
            }
            return decrypted;
        } catch (Exception e) {
            return data; // Fail-Open
        }
    }
    
    // =========================
    // Atomic wrappers
    // =========================
    
    private String encryptAtomically(String plain) {
        try {
            String cipher = doEncryptInternal(plain);
            
            // Atomic validation: decrypt(cipher) must equal original plain
            String check = doDecryptInternal(cipher);
            if (plain.equals(check)) {
                return cipher;
            }
            
            return plain;
        } catch (Exception e) {
            return plain;
        }
    }
    
    private String decryptAtomically(String input) {
        try {
            String plain = doDecryptInternal(input);
            
            // If decrypt produced same as input, it could be:
            // - input already plain
            // - or decrypt failed and fell back inside parts
            // We need a deterministic check to avoid producing garbage.
            // Validate by re-encrypting the decrypted result:
            // If input is a real cipher, encrypt(plain) should equal input.
            // If not, return input (Fail-Open).
            String reEncrypt = doEncryptInternal(plain);
            if (input.equals(reEncrypt)) {
                return plain; // valid cipher -> decrypted
            }
            
            // Not a valid cipher: return original input (likely plain)
            return input;
        } catch (Exception e) {
            return input;
        }
    }
    
    // =========================
    // Internal (may throw)
    // Keep your existing behavior, but do NOT decide success here.
    // =========================
    
    private String doEncryptInternal(String data) {
        // Keep your split behavior (you said ignore split topic for now)
        if (data.contains(" ")) {
            // NOTE: original used split(" "), which loses consecutive spaces; kept as-is.
            String[] parts = data.split(" ");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parts.length; i++) {
                sb.append(getEncryptDateOrThrow(parts[i]));
                if (i < parts.length - 1) {
                    sb.append(' ');
                }
            }
            return sb.toString().trim();
        }
        return getEncryptDateOrThrow(data);
    }
    
    private String doDecryptInternal(String data) {
        if (data.contains(" ")) {
            String[] parts = data.split(" ");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parts.length; i++) {
                sb.append(getDecryptDataOrThrow(parts[i]));
                if (i < parts.length - 1) {
                    sb.append(' ');
                }
            }
            return sb.toString().trim();
        }
        return getDecryptDataOrThrow(data);
    }
    
    // =========================
    // Core encrypt/decrypt piece (throw on partial failure)
    // =========================
    
    private String getEncryptDateOrThrow(String data) {
        // Treat empty token safely
        if (data == null) {
            throw new IllegalArgumentException("encrypt token is null");
        }
        if (data.isEmpty()) {
            return "";
        }
        
        // === Your original logic starts ===
        boolean isNumeric = "0123456789".equals(numberMapperStr);
        
        if (isNumeric && data.length() > 1) {
            String firstDigitSet = numberMapperStr.substring(1); // "123456789"
            char firstChar = data.charAt(0);
            int iFirst = firstDigitSet.indexOf(firstChar);
            if (iFirst == -1) {
                iFirst = 0; // tolerance
            }
            int jFirst = (sortCode) % firstDigitSet.length();
            int index = (iFirst + jFirst) % firstDigitSet.length();
            char encFirst = firstDigitSet.charAt(index);
            
            String rest = data.substring(1);
            String encRest;
            if (rest.isEmpty()) {
                encRest = "";
            } else if (rest.length() < 2 || Math.pow(this.mapper.getRadix(), rest.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
                List<String> list = toList(rest);
                StringBuilder encrypt = new StringBuilder();
                for (int idx = 0; idx < list.size(); idx++) {
                    String s = list.get(idx);
                    int i = numberMapperStr.indexOf(s);
                    int j = (sortCode + idx + 1) % numberMapperStr.length();
                    int idxEnc = (i + j) % numberMapperStr.length();
                    encrypt.append(numberMapperStr.charAt(idxEnc));
                }
                encRest = encrypt.toString();
            } else {
                List<String> plainValues = checkArgs(this.mapper.getRadix(), rest);
                StringBuilder encryptedText = new StringBuilder();
                for (String plainValue : plainValues) {
                    // char[] encrypt must not silently "fail"
                    char[] enc = encrypt(plainValue.toCharArray());
                    if (enc == null) {
                        throw new IllegalStateException("encrypt(char[]) returned null");
                    }
                    String encPart = new String(enc);
                    
                    // If encryption produced identical string, treat as failure (avoid partial corruption)
                    if (encPart.equals(plainValue)) {
                        throw new IllegalStateException("encrypt(char[]) no-op for chunk");
                    }
                    encryptedText.append(encPart);
                }
                encRest = encryptedText.toString();
            }
            return encFirst + encRest;
        }
        
        if (data.length() < 2 || Math.pow(this.mapper.getRadix(), data.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
            List<String> list = toList(data);
            StringBuilder encrypt = new StringBuilder();
            for (int idx = 0; idx < list.size(); idx++) {
                String s = list.get(idx);
                int i = numberMapperStr.indexOf(s);
                int j = (sortCode + idx) % numberMapperStr.length();
                int index = (i + j) % numberMapperStr.length();
                encrypt.append(numberMapperStr.charAt(index));
            }
            return encrypt.toString();
        }
        
        List<String> plainValues = checkArgs(this.mapper.getRadix(), data);
        StringBuilder encryptedText = new StringBuilder();
        for (String plainValue : plainValues) {
            char[] enc = encrypt(plainValue.toCharArray());
            if (enc == null) {
                throw new IllegalStateException("encrypt(char[]) returned null");
            }
            String encPart = new String(enc);
            if (encPart.equals(plainValue)) {
                throw new IllegalStateException("encrypt(char[]) no-op for chunk");
            }
            encryptedText.append(encPart);
        }
        return encryptedText.toString();
        // === Your original logic ends ===
    }
    
    private String getDecryptDataOrThrow(String data) {
        if (data == null) {
            throw new IllegalArgumentException("decrypt token is null");
        }
        if (data.isEmpty()) {
            return "";
        }
        
        boolean isNumeric = "0123456789".equals(numberMapperStr);
        
        if (isNumeric && data.length() > 1) {
            String firstDigitSet = numberMapperStr.substring(1); // "123456789"
            char firstChar = data.charAt(0);
            int iFirst = firstDigitSet.indexOf(firstChar);
            if (iFirst == -1) {
                iFirst = 0;
            }
            int jFirst = (sortCode) % firstDigitSet.length();
            int index = iFirst - jFirst;
            if (index < 0) {
                index = (firstDigitSet.length() + index) % firstDigitSet.length();
            }
            char decFirst = firstDigitSet.charAt(index);
            
            String rest = data.substring(1);
            String decRest;
            if (rest.isEmpty()) {
                decRest = "";
            } else if (rest.length() < 2 || Math.pow(this.mapper.getRadix(), rest.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
                List<String> list = toList(rest);
                StringBuilder decrypt = new StringBuilder();
                for (int idx = 0; idx < list.size(); idx++) {
                    String s = list.get(idx);
                    int j = (sortCode + idx + 1) % numberMapperStr.length();
                    int i = numberMapperStr.indexOf(s);
                    int idxDec = i - j;
                    if (idxDec < 0) {
                        idxDec = (numberMapperStr.length() + idxDec) % numberMapperStr.length();
                    }
                    decrypt.append(numberMapperStr.charAt(idxDec));
                }
                decRest = decrypt.toString();
            } else {
                List<String> cipherChunks = checkArgs(this.mapper.getRadix(), rest);
                StringBuilder decryptedText = new StringBuilder();
                for (String cipherChunk : cipherChunks) {
                    char[] dec = decrypt(cipherChunk.toCharArray());
                    if (dec == null) {
                        throw new IllegalStateException("decrypt(char[]) returned null");
                    }
                    String decPart = new String(dec);
                    
                    if (decPart.equals(cipherChunk)) {
                        throw new IllegalStateException("decrypt(char[]) fallback for chunk");
                    }
                    decryptedText.append(decPart);
                }
                decRest = decryptedText.toString();
            }
            return decFirst + decRest;
        }
        
        if (data.length() < 2 || Math.pow(this.mapper.getRadix(), data.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
            List<String> list = toList(data);
            StringBuilder decrypt = new StringBuilder();
            for (int idx = 0; idx < list.size(); idx++) {
                String s = list.get(idx);
                int j = (sortCode + idx) % numberMapperStr.length();
                int i = numberMapperStr.indexOf(s);
                int index = i - j;
                if (index < 0) {
                    index = (numberMapperStr.length() + index) % numberMapperStr.length();
                }
                decrypt.append(numberMapperStr.charAt(index));
            }
            return decrypt.toString();
        }
        
        List<String> cipherChunks = checkArgs(this.mapper.getRadix(), data);
        StringBuilder decryptedText = new StringBuilder();
        for (String cipherChunk : cipherChunks) {
            char[] dec = decrypt(cipherChunk.toCharArray());
            if (dec == null) {
                throw new IllegalStateException("decrypt(char[]) returned null");
            }
            String decPart = new String(dec);
            if (decPart.equals(cipherChunk)) {
                throw new IllegalStateException("decrypt(char[]) fallback for chunk");
            }
            decryptedText.append(decPart);
        }
        return decryptedText.toString();
    }
    
    // private String getEncryptDate(String data) {
    // boolean isNumeric = "0123456789".equals(numberMapperStr);
    // if (isNumeric && data.length() > 1) {
    // // 首位用1-9做简单加密
    // String firstDigitSet = numberMapperStr.substring(1); // "123456789"
    // char firstChar = data.charAt(0);
    // int iFirst = firstDigitSet.indexOf(firstChar);
    // if (iFirst == -1)
    // iFirst = 0; // 容错
    // int jFirst = (sortCode) % firstDigitSet.length();
    // int index = (iFirst + jFirst) % firstDigitSet.length();
    // char encFirst = firstDigitSet.charAt(index);
    // // 剩余部分走原有逻辑
    // String rest = data.substring(1);
    // String encRest;
    // if (rest.isEmpty()) {
    // encRest = "";
    // } else if (rest.length() < 2 || Math.pow(this.mapper.getRadix(), rest.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
    // List<String> list = toList(rest);
    // StringBuilder encrypt = new StringBuilder();
    // for (int idx = 0; idx < list.size(); idx++) {
    // String s = list.get(idx);
    // int i = numberMapperStr.indexOf(s);
    // int j = (sortCode + idx + 1) % numberMapperStr.length(); // idx+1保证扰动不和首位重复
    // int idxEnc = (i + j) % numberMapperStr.length();
    // encrypt.append(numberMapperStr.charAt(idxEnc));
    // }
    // encRest = encrypt.toString();
    // } else {
    // List<String> plainValues = checkArgs(this.mapper.getRadix(), rest);
    // StringBuilder encryptedText = new StringBuilder();
    // for (String plainValue : plainValues) {
    // encryptedText.append(new String(encrypt(plainValue.toCharArray())));
    // }
    // encRest = encryptedText.toString();
    // }
    // return encFirst + encRest;
    // }
    // // 非数字集或长度为1，走原有逻辑
    // if (data.length() < 2 || Math.pow(this.mapper.getRadix(), data.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
    // List<String> list = toList(data);
    // StringBuilder encrypt = new StringBuilder();
    // for (int idx = 0; idx < list.size(); idx++) {
    // String s = list.get(idx);
    // int i = numberMapperStr.indexOf(s);
    // int j = (sortCode + idx) % numberMapperStr.length(); // 每位扰动
    // int index = (i + j) % numberMapperStr.length();
    // encrypt.append(numberMapperStr.charAt(index));
    // }
    // return encrypt.toString();
    // }
    // List<String> plainValues = checkArgs(this.mapper.getRadix(), data);
    // StringBuilder encryptedText = new StringBuilder();
    // for (String plainValue : plainValues) {
    // encryptedText.append(new String(encrypt(plainValue.toCharArray())));
    // }
    // return encryptedText.toString();
    // }
    //
    // private String getDecryptData(String data) {
    // boolean isNumeric = "0123456789".equals(numberMapperStr);
    // if (isNumeric && data.length() > 1) {
    // // 首位用1-9做简单解密
    // String firstDigitSet = numberMapperStr.substring(1); // "123456789"
    // char firstChar = data.charAt(0);
    // int iFirst = firstDigitSet.indexOf(firstChar);
    // if (iFirst == -1)
    // iFirst = 0; // 容错
    // int jFirst = (sortCode) % firstDigitSet.length();
    // int index = iFirst - jFirst;
    // if (index < 0) {
    // index = (firstDigitSet.length() + index) % firstDigitSet.length();
    // }
    // char decFirst = firstDigitSet.charAt(index);
    // // 剩余部分走原有逻辑
    // String rest = data.substring(1);
    // String decRest;
    // if (rest.length() == 0) {
    // decRest = "";
    // } else if (rest.length() < 2 || Math.pow(this.mapper.getRadix(), rest.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
    // List<String> list = toList(rest);
    // StringBuilder decrypt = new StringBuilder();
    // for (int idx = 0; idx < list.size(); idx++) {
    // String s = list.get(idx);
    // int j = (sortCode + idx + 1) % numberMapperStr.length();
    // int i = numberMapperStr.indexOf(s);
    // int idxDec = i - j;
    // if (idxDec < 0) {
    // idxDec = (numberMapperStr.length() + idxDec) % numberMapperStr.length();
    // }
    // decrypt.append(numberMapperStr.charAt(idxDec));
    // }
    // decRest = decrypt.toString();
    // } else {
    // List<String> plainValues = checkArgs(this.mapper.getRadix(), rest);
    // StringBuilder decryptedText = new StringBuilder();
    // for (String plainValue : plainValues) {
    // decryptedText.append(new String(decrypt(plainValue.toCharArray())));
    // }
    // decRest = decryptedText.toString();
    // }
    // return decFirst + decRest;
    // }
    // // 非数字集或长度为1，走原有逻辑
    // if (data.length() < 2 || Math.pow(this.mapper.getRadix(), data.getBytes(StandardCharsets.UTF_8).length) < 1000000) {
    // List<String> list = toList(data);
    // StringBuilder decrypt = new StringBuilder();
    // for (int idx = 0; idx < list.size(); idx++) {
    // String s = list.get(idx);
    // int j = (sortCode + idx) % numberMapperStr.length();
    // int i = numberMapperStr.indexOf(s);
    // int index = i - j;
    // if (index < 0) {
    // index = (numberMapperStr.length() + index) % numberMapperStr.length();
    // }
    // decrypt.append(numberMapperStr.charAt(index));
    // }
    // return decrypt.toString();
    // }
    // List<String> plainValues = checkArgs(this.mapper.getRadix(), data);
    // StringBuilder decryptedText = new StringBuilder();
    // for (String plainValue : plainValues) {
    // decryptedText.append(new String(decrypt(plainValue.toCharArray())));
    // }
    // return decryptedText.toString();
    // }
    //
    // public String encrypt(String data) {
    // String encryptData = "";
    // if (null == data) {
    // return null;
    // } else {
    // String[] s = null;
    // try {
    // if (data.contains(" ")) {
    // s = data.split(" ");
    // }
    // if (s != null) {
    // for (String string : s) {
    // encryptData += getEncryptDate(string);
    // encryptData += " ";
    // }
    // encryptData = encryptData.trim();
    // }
    // return encryptData.isEmpty() ? getEncryptDate(data) : encryptData;
    //
    // } catch (Exception e) {
    // // e.printStackTrace();
    // return data;
    // }
    // }
    // }
    
    private List<String> toList(String data) {
        List<String> list = new ArrayList();
        
        for (char c : data.toCharArray()) {
            list.add(String.valueOf(c));
        }
        
        return list;
    }
    
    // public char[] encrypt(char[] data) {
    // return null == data ? null : this.mapper.convertToChars(this.sm4.encrypt(this.mapper.convertToIndexes(data)));
    // }
    //
    // public String decrypt(String data) {
    // if (null == data) {
    // return null;
    // } else {
    // try {
    // if (data.contains(" ")) {
    // String[] s = data.split(" ");
    // String decryptData = "";
    // for (String string : s) {
    // decryptData += getDecryptData(string);
    // decryptData += " ";
    // }
    // return decryptData.trim();
    // }
    // return getDecryptData(data);
    // } catch (Exception e) {
    // e.printStackTrace();
    // return data;
    // }
    // }
    // }
    //
    // public char[] decrypt(char[] data) {
    // if (null == data) {
    // return null;
    // } else {
    // try {
    // return this.mapper.convertToChars(this.sm4.decrypt(this.mapper.convertToIndexes(data)));
    // } catch (Exception var3) {
    // return data;
    // }
    // }
    // }
    
    private List<String> checkArgs(int radix, String data) {
        List<String> sourceList = new ArrayList();
        int maxLen = 2 * (int) Math.floor(Math.log(TWO_TO_96) / Math.log((double) radix));
        if (data.getBytes(StandardCharsets.UTF_8).length > maxLen) {
            sourceList = this.splitString(data, maxLen);
        } else {
            sourceList.add(data);
        }
        
        return sourceList;
    }
    
    private List<String> splitString(String str, int chunkSize) {
        List<String> chunks = new ArrayList();
        int length = str.length();
        
        for (int i = 0; i < length; i += chunkSize) {
            int end = Math.min(i + chunkSize, length);
            chunks.add(str.substring(i, end));
        }
        
        return chunks;
    }
    
    public static enum FPEMode {
        
        FF1("FF1"),
        FF3_1("FF3-1");
        
        private final String value;
        
        private FPEMode(String name) {
            this.value = name;
        }
        
        public String getValue() {
            return this.value;
        }
    }
}
