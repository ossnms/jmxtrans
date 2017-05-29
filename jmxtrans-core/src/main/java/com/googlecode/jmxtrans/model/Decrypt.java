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

import com.google.common.base.Strings;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class Decrypt {
	private static final String CIPHER_STRING = "DES/CBC/PKCS5Padding";
	private static final byte[] INIT_VECTOR = new byte[]{100, -78, -30, 20, 32, 71, 94, 95};

	private enum CipherType {
		ENCRYPT, DECRYPT
	}

	private Cipher buildCipher(CipherType type) {
		try {
			final Cipher cipher = Cipher.getInstance(CIPHER_STRING);
			final IvParameterSpec parameterSpec = new IvParameterSpec(INIT_VECTOR);
			final String key = loadKey();
			final SecretKey secretKey = new SecretKeySpec(key.getBytes(getCharset()), "DES");
			cipher.init(type == CipherType.DECRYPT ? 2 : 1, secretKey, parameterSpec);
			return cipher;
		} catch (NoSuchAlgorithmException|NoSuchPaddingException
				|InvalidAlgorithmParameterException|InvalidKeyException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private String loadKey() {
		try (InputStream stream = getClass().getResourceAsStream("/config.properties")) {
			final Properties properties = new Properties();
			properties.load(stream);
			final String key = properties.getProperty("secure.key");
			if (Strings.isNullOrEmpty(key)) {
				throw new IllegalStateException("No secure key defined.");
			}
			return key;
		} catch (IOException ex) {
			throw new IllegalStateException("Configuration file access error.", ex);
		}
	}

	private static Charset getCharset() {
		return Charset.forName("UTF8");
	}

	synchronized String decrypt(final String encryptedString) {
		if (encryptedString == null) {
			return null;
		}
		try {
			final byte[] decryptedBytes =
					buildCipher(CipherType.DECRYPT).doFinal(DatatypeConverter.parseHexBinary(encryptedString));
			return new String(decryptedBytes, getCharset());
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			throw new IllegalStateException(ex);
		}
	}

	String encrypt(String original) {
		if (original == null) {
			return null;
		}
		try {
			final byte[] encryptedBytes = buildCipher(CipherType.ENCRYPT)
					.doFinal(original.getBytes(getCharset()));
			return DatatypeConverter.printHexBinary(encryptedBytes);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
