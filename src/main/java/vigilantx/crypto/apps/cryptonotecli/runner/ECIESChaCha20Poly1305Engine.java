package vigilantx.crypto.apps.cryptonotecli.runner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Класс для шифрования и расшифрования данных с использованием ECIES и
 * ChaCha20-Poly1305. Этот класс реализует механизм безопасного обмена данными,
 * где ключи инициализации (IV) и ключи шифрования передаются с помощью ECIES
 * (Elliptic Curve Integrated Encryption Scheme), а сами данные шифруются
 * алгоритмом ChaCha20-Poly1305.
 */
public final class ECIESChaCha20Poly1305Engine {
	/**
	 * Расшифровывает данные, используя закрытый ключ получателя.
	 *
	 * @param reciever Ключевая пара получателя, содержащая закрытый ключ.
	 * @param source   Поток входных данных, содержащий зашифрованное сообщение.
	 * @return Поток расшифрованных данных.
	 * @throws IOException                        В случае ошибки ввода-вывода.
	 * @throws NoSuchAlgorithmException           Если алгоритм шифрования не
	 *                                            найден.
	 * @throws InvalidKeySpecException            Если ключи имеют неверную
	 *                                            спецификацию.
	 * @throws InvalidKeyException                Если ключи некорректны.
	 * @throws NoSuchPaddingException             Если используется неподдерживаемая
	 *                                            схема дополнения.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            недействительны.
	 * @throws IllegalBlockSizeException          Если размер блока данных
	 *                                            некорректен.
	 * @throws BadPaddingException                Если данные имеют неверное
	 *                                            дополнение.
	 */
	public static InputStream decrypt(final KeyPair reciever, final InputStream source)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		final var publicKeyArray = INettyIO.INSTANCE.readArrayByInt(source);
		final var sender = SECP521R1.deserializeKey(publicKeyArray);

		// Чтение зашифрованного ключа и IV
		final var keyIvEncrypted = INettyIO.INSTANCE.readArrayByInt(source);
		final var keyIv = SECP521R1.decryptBytes(reciever.getPrivate(), sender, keyIvEncrypted);

		// Разделение ключа и IV
		final var key = new byte[32]; // Размер ключа ChaCha20-Poly1305 - 32 байта
		final var iv = new byte[12]; // Размер IV ChaCha20-Poly1305 - 12 байт
		System.arraycopy(keyIv, 0, key, 0, key.length);
		System.arraycopy(keyIv, key.length, iv, 0, iv.length);

		final var keyS = ChaCha20Poly1305Algo.deserializeKey(key);
		final var cipher = Cipher.getInstance(ChaCha20Poly1305Algo.ALGORITHM, VXCryptoNoteCliRunner.PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, keyS, new IvParameterSpec(iv));
		return new CipherInputStream(source, cipher);
	}

	/**
	 * Шифрует данные, используя ECIES для защиты ключа и IV.
	 *
	 * @param sender   Ключевая пара отправителя.
	 * @param reciever Открытый ключ получателя.
	 * @param output   Поток вывода, куда будет записан зашифрованный результат.
	 * @param source   Поток входных данных, которые нужно зашифровать.
	 * @throws IOException                        В случае ошибки ввода-вывода.
	 * @throws NoSuchAlgorithmException           Если алгоритм шифрования не
	 *                                            найден.
	 * @throws InvalidKeyException                Если ключи некорректны.
	 * @throws NoSuchPaddingException             Если используется неподдерживаемая
	 *                                            схема дополнения.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            недействительны.
	 * @throws IllegalBlockSizeException          Если размер блока данных
	 *                                            некорректен.
	 * @throws BadPaddingException                Если данные имеют неверное
	 *                                            дополнение.
	 */
	public static void encrypt(final KeyPair sender, final PublicKey reciever, final OutputStream output,
			final InputStream source) throws IOException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Objects.requireNonNull(output);
		Objects.requireNonNull(source);

		// Запись публичного ключа отправителя
		final var senderPublicKeyData = sender.getPublic().getEncoded();
		INettyIO.INSTANCE.writeIntArray(output, senderPublicKeyData);

		// Генерация ключа и IV для ChaCha20-Poly1305
		final var keyS = ChaCha20Poly1305Algo.generateKey();
		final var key = keyS.getEncoded();
		final var iv = ChaCha20Poly1305Algo.generateIV();

		// Защита ключа и IV с помощью ECIES
		final var keyIv = new byte[key.length + iv.length];
		System.arraycopy(key, 0, keyIv, 0, key.length);
		System.arraycopy(iv, 0, keyIv, key.length, iv.length);
		final var keyIvEncrypted = SECP521R1.encryptBytes(sender.getPrivate(), reciever, keyIv);
		INettyIO.INSTANCE.writeIntArray(output, keyIvEncrypted);
		final var cipher = Cipher.getInstance(ChaCha20Poly1305Algo.ALGORITHM, VXCryptoNoteCliRunner.PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, keyS, new IvParameterSpec(iv));
		try (var cipherOutputStream = new CipherOutputStream(output, cipher)) {
			source.transferTo(cipherOutputStream);
		}
	}

	/**
	 * Закрытый конструктор, предотвращающий создание экземпляров класса.
	 */
	private ECIESChaCha20Poly1305Engine() {

	}
}