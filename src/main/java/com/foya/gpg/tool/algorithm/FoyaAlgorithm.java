package com.foya.gpg.tool.algorithm;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public class FoyaAlgorithm {
	public static String publicKeyAlgorithmTags(int algId) {
		switch (algId) {
			case PublicKeyAlgorithmTags.RSA_GENERAL:
				return "RSA_GENERAL";
			case PublicKeyAlgorithmTags.RSA_ENCRYPT:
				return "RSA_ENCRYPT";
			case PublicKeyAlgorithmTags.RSA_SIGN:
				return "RSA_SIGN";
			case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
				return "ELGAMAL_ENCRYPT";
			case PublicKeyAlgorithmTags.DSA:
				return "DSA";
			case PublicKeyAlgorithmTags.ECDH:
				return "ECDH";
			case PublicKeyAlgorithmTags.ECDSA:
				return "ECDSA";
			case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
				return "ELGAMAL_GENERAL";
			case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
				return "DIFFIE_HELLMAN";
		}

		return "unknown";
	}

	public static String pgpCompressedDataAlgorithmTags(int algId) {
		switch (algId) {
			case CompressionAlgorithmTags.BZIP2:
				return "BZIP2";
			case CompressionAlgorithmTags.UNCOMPRESSED:
				return "UNCOMPRESSED";
			case CompressionAlgorithmTags.ZIP:
				return "ZIP";
			case CompressionAlgorithmTags.ZLIB:
				return "ZLIB";
		}

		return "unknown";
	}
}
