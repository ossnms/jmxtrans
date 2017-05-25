/**
 * The MIT License
 * Copyright © 2010 JmxTrans team
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.googlecode.jmxtrans.model;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static java.lang.System.out;

public class Decrypt {
	private static final String CIPHER_STRING = "DES/CBC/PKCS5Padding";
	private static final byte[] INIT_VECTOR = new byte[]{100, -78, -30, 20, 32, 71, 94, 95};
	private static final String KEY = "m\"HFX8$.";

	private enum CipherType {
		ENCRYPT, DECRYPT
	}

	public static void main(String[] args) {
		if (args.length < 1) {
			out.println("The first parameter must be the string to encrypt.");
		} else {
			out.println("Encryption of " + args[0] + " resulted in " + new Decrypt().encrypt(args[0]));
		}
	}

	private Cipher buildCipher(CipherType type) {
		try {
			final Cipher cipher = Cipher.getInstance(CIPHER_STRING);
			final IvParameterSpec parameterSpec = new IvParameterSpec(INIT_VECTOR);
			final SecretKey secretKey = new SecretKeySpec(KEY.getBytes(), "DES");
			cipher.init(type == CipherType.DECRYPT ? 2 : 1, secretKey, parameterSpec);
			return cipher;
		} catch (NoSuchAlgorithmException|NoSuchPaddingException
				|InvalidAlgorithmParameterException|InvalidKeyException ex) {
			throw new IllegalStateException(ex);
		}
	}

	synchronized String decrypt(final String encryptedString) {
		if (encryptedString == null) {
			return null;
		}
		try {
			final byte[] decryptedBytes =
					buildCipher(CipherType.DECRYPT).doFinal(DatatypeConverter.parseHexBinary(encryptedString));
			return new String(decryptedBytes);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private String encrypt(String original) {
		if (original == null) {
			return null;
		}
		try {
			final byte[] encryptedBytes = buildCipher(CipherType.ENCRYPT).doFinal(original.getBytes());
			return DatatypeConverter.printHexBinary(encryptedBytes);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
