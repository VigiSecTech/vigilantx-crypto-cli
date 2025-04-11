package vigilantx.crypto.apps.cryptonotecli.runner;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * Утилитарный класс для работы с алгоритмом ChaCha20-Poly1305.
 *
 *
 *
 * Этот класс предоставляет методы для шифрования и дешифрования данных,
 *
 * а также для генерации ключей и векторов инициализации (IV).
 */
public final class ChaCha20Poly1305Algo {
	/** Название алгоритма. */
	public static final String ALGORITHM = "ChaCha20-Poly1305";
	/** Размер ключа в битах. */
	public static final int KEY_SIZE = 256;
	/** Размер вектора инициализации (IV) в байтах. */
	public static final int IV_SIZE = 12;

	/**
	 * Расшифровывает переданный зашифрованный текст.
	 *
	 * @param ciphertext Зашифрованные данные в виде массива байтов.
	 * @param secretKey  Секретный ключ для дешифрования.
	 * @param iv         Вектор инициализации (IV).
	 * @return Расшифрованные данные в виде строки.
	 * @throws GeneralSecurityException В случае ошибки дешифрования.
	 */
	public static String decrypt(final byte[] ciphertext, final SecretKey secretKey, final byte[] iv)
			throws GeneralSecurityException {
		final var cipher = Cipher.getInstance(ChaCha20Poly1305Algo.ALGORITHM, VXCryptoNoteCliRunner.PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		final var decryptedBytes = cipher.doFinal(ciphertext);
		return new String(decryptedBytes);
	}

	/**
	 * Восстанавливает секретный ключ из массива байтов.
	 *
	 * @param keyBytes Массив байтов, содержащий ключ.
	 * @return Объект {@link SecretKey}.
	 */
	public static SecretKey deserializeKey(final byte[] keyBytes) {
		return new SecretKeySpec(keyBytes, ChaCha20Poly1305Algo.ALGORITHM);
	}

	/**
	 * Шифрует переданные данные.
	 *
	 * @param plaintext Открытый текст в виде массива байтов.
	 * @param secretKey Секретный ключ.
	 * @param iv        Вектор инициализации (IV).
	 * @return Зашифрованные данные в виде массива байтов.
	 * @throws GeneralSecurityException В случае ошибки шифрования.
	 */
	public static byte[] encrypt(final byte[] plaintext, final SecretKey secretKey, final byte[] iv)
			throws GeneralSecurityException {
		final var cipher = Cipher.getInstance(ChaCha20Poly1305Algo.ALGORITHM, VXCryptoNoteCliRunner.PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		return cipher.doFinal(plaintext);
	}

	/**
	 * Генерирует случайный вектор инициализации (IV) фиксированного размера.
	 *
	 * @return Массив байтов, содержащий IV.
	 * @throws NoSuchAlgorithmException В случае ошибки генерации.
	 */
	public static byte[] generateIV() throws NoSuchAlgorithmException {
		return ChaCha20Poly1305Algo.generateIV(ChaCha20Poly1305Algo.IV_SIZE);
	}

	/**
	 * Генерирует случайный вектор инициализации (IV) заданного размера.
	 *
	 * @param size Размер IV в байтах.
	 * @return Сгенерированный IV.
	 * @throws NoSuchAlgorithmException В случае ошибки генерации.
	 */
	public static byte[] generateIV(final int size) throws NoSuchAlgorithmException {
		final var iv = new byte[size];
		final var random = SecureRandom.getInstanceStrong();
		random.nextBytes(iv);
		return iv;
	}

	/**
	 * Создает новый случайный секретный ключ фиксированного размера.
	 *
	 * @return Секретный ключ.
	 * @throws NoSuchAlgorithmException В случае ошибки генерации.
	 */
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
		return ChaCha20Poly1305Algo.generateKey(ChaCha20Poly1305Algo.KEY_SIZE);
	}

	/**
	 * Создает новый случайный секретный ключ заданного размера.
	 *
	 * @param keySize Размер ключа в битах.
	 * @return Секретный ключ.
	 * @throws NoSuchAlgorithmException В случае ошибки генерации.
	 */
	public static SecretKey generateKey(final int keySize) throws NoSuchAlgorithmException {
		final var keyGen = KeyGenerator.getInstance(ChaCha20Poly1305Algo.ALGORITHM, VXCryptoNoteCliRunner.PROVIDER);
		keyGen.init(keySize);
		return keyGen.generateKey();
	}

	/**
	 * Сериализует секретный ключ в массив байтов.
	 *
	 * @param secretKey Секретный ключ.
	 * @return Массив байтов, содержащий ключ.
	 */
	public static byte[] serializeKey(final Key secretKey) { return secretKey.getEncoded(); }

	/**
	 * Закрытый конструктор для предотвращения создания экземпляров класса.
	 */
	private ChaCha20Poly1305Algo() { /* чтобы запретить создание экземпляров класса. */ }
}