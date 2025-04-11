package vigilantx.crypto.apps.cryptonotecli.runner;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

/**
 * Класс {@code SECP521R1} предоставляет методы для выполнения операций
 * шифрования и дешифрования с использованием алгоритма ECIES (Elliptic Curve
 * Integrated Encryption Scheme) на базе кривой SECP521R1. Класс включает
 * утилитарные методы для шифрования и дешифрования с использованием
 * эллиптической криптографии.
 */
public final class SECP521R1 {
	/**
	 * Создает объект {@code Cipher} для шифрования или дешифрования с
	 * использованием ECIES.
	 *
	 * @param privateKey Приватный ключ, используемый для инициализации шифра.
	 * @param publicKey  Публичный ключ, используемый для инициализации шифра.
	 * @param mode       Режим работы шифра: {@link Cipher#ENCRYPT_MODE} или
	 *                   {@link Cipher#DECRYPT_MODE}.
	 * @return Инициализированный объект {@code Cipher}.
	 * @throws NoSuchAlgorithmException           Если алгоритм не найден.
	 * @throws NoSuchPaddingException             Если паддинг не поддерживается.
	 * @throws InvalidKeyException                Если ключ недействителен.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 */
	public static Cipher cipher(final PrivateKey privateKey, final PublicKey publicKey, final int mode)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		final var cipher = Cipher.getInstance("ECIES/None/NoPadding", VXCryptoNoteCliRunner.PROVIDER);
		final var param = new IESParameterSpec(null, null, 256);
		cipher.init(mode, new IEKeySpec(privateKey, publicKey), param);
		return cipher;
	}

	/**
	 * Создает объект {@code Cipher} для дешифрования с использованием ECIES.
	 *
	 * @param reciever        Приватный ключ получателя.
	 * @param senderPublicKey Публичный ключ отправителя.
	 * @return Инициализированный объект {@code Cipher} для дешифрования.
	 * @throws InvalidKeyException                Если ключ недействителен.
	 * @throws NoSuchAlgorithmException           Если алгоритм не найден.
	 * @throws NoSuchPaddingException             Если паддинг не поддерживается.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 */
	public static Cipher cipherDecrypt(final PrivateKey reciever, final PublicKey senderPublicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException {
		return SECP521R1.cipher(reciever, senderPublicKey, Cipher.DECRYPT_MODE);
	}

	/**
	 * Создает объект {@code Cipher} для шифрования с использованием ECIES.
	 *
	 * @param senderPrivateKey   Приватный ключ отправителя.
	 * @param recipientPublicKey Публичный ключ получателя.
	 * @return Инициализированный объект {@code Cipher} для шифрования.
	 * @throws InvalidKeyException                Если ключ недействителен.
	 * @throws NoSuchAlgorithmException           Если алгоритм не найден.
	 * @throws NoSuchPaddingException             Если паддинг не поддерживается.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 */
	public static Cipher cipherEncrypt(final PrivateKey senderPrivateKey, final PublicKey recipientPublicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException {
		return SECP521R1.cipher(senderPrivateKey, recipientPublicKey, Cipher.ENCRYPT_MODE);
	}

	/**
	 * Дешифрует массив байтов с использованием ECIES.
	 *
	 * @param reciever Приватный ключ получателя.
	 * @param sender   Публичный ключ отправителя.
	 * @param data     Данные для дешифрования.
	 * @return Дешифрованный массив байтов.
	 * @throws InvalidKeyException                Если ключ недействителен.
	 * @throws NoSuchAlgorithmException           Если алгоритм не найден.
	 * @throws NoSuchPaddingException             Если паддинг не поддерживается.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 * @throws IllegalBlockSizeException          Если размер блока некорректен.
	 * @throws BadPaddingException                Если паддинг данных неверен.
	 */
	public static byte[] decryptBytes(final PrivateKey reciever, final PublicKey sender, final byte[] data)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final var cipher = SECP521R1.cipherDecrypt(reciever, sender);
		cipher.update(data);
		return cipher.doFinal();
	}

	/**
	 * Десериализует публичный ключ из массива байтов.
	 *
	 * @param publicKeyArray Массив байтов, представляющий публичный ключ.
	 * @return Десериализованный публичный ключ.
	 * @throws NoSuchAlgorithmException Если алгоритм не найден.
	 * @throws InvalidKeySpecException  Если ключ не соответствует необходимому
	 *                                  формату.
	 */
	public static PublicKey deserializeKey(final byte[] publicKeyArray)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		final var senderEncodedKeySpec = new X509EncodedKeySpec(publicKeyArray);
		final var kf = KeyFactory.getInstance("ECDH", VXCryptoNoteCliRunner.PROVIDER);
		return kf.generatePublic(senderEncodedKeySpec);
	}

	/**
	 * Шифрует массив байтов с использованием ECIES.
	 *
	 * @param senderPrivateKey Приватный ключ отправителя.
	 * @param reciever         Публичный ключ получателя.
	 * @param data             Данные для шифрования.
	 * @return Зашифрованный массив байтов.
	 * @throws InvalidKeyException                Если ключ недействителен.
	 * @throws NoSuchAlgorithmException           Если алгоритм не найден.
	 * @throws NoSuchPaddingException             Если паддинг не поддерживается.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 * @throws IllegalBlockSizeException          Если размер блока некорректен.
	 * @throws BadPaddingException                Если паддинг данных неверен.
	 */
	public static byte[] encryptBytes(final PrivateKey senderPrivateKey, final PublicKey reciever, final byte[] data)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final var cipher = SECP521R1.cipherEncrypt(senderPrivateKey, reciever);
		cipher.update(data);
		return cipher.doFinal();
	}

	/**
	 * Запрещаем создание объекта этого класса
	 */
	private SECP521R1() { /* Запрещаем создание объекта этого класса */ }
}