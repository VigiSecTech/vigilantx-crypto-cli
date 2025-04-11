package vigilantx.crypto.apps.cryptonotecli.runner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

/**
 * Основной класс программы для выполнения операций с хранилищем ключей и
 * криптографическими данными.
 *
 * <p>
 * Этот класс предоставляет интерфейс командной строки для выполнения различных
 * операций, таких как генерация ключей, шифрование, дешифрование, экспорт и
 * импорт ключей.
 * </p>
 *
 * <p>
 * Программа поддерживает следующие операции:
 * </p>
 *
 * <ul>
 * <li><strong>keyGen</strong> - Генерация ключа и сертификата</li>
 * <li><strong>keyList</strong> - Вывод содержимого хранилища</li>
 * <li><strong>keyExport</strong> - Экспорт ключа в файл</li>
 * <li><strong>keyImport</strong> - Импорт ключа из файла</li>
 * <li><strong>decrypt</strong> - Дешифрование данных</li>
 * <li><strong>encrypt</strong> - Шифрование данных</li>
 * </ul>
 *
 * <p>
 * Программа работает с хранилищем ключей и сертификатов, используя библиотеку
 * BouncyCastle для криптографических операций.
 * </p>
 *
 * <p>
 * Пример использования:
 * </p>
 *
 * <pre>
 * java -jar VXCryptoNoteCliRunner.jar [keystore_path] [operation] [arguments]
 * </pre>
 *
 * <p>
 * Например, для генерации ключа:
 * </p>
 *
 * <pre>
 * java -jar VXCryptoNoteCliRunner.jar keystore keyGen user1
 * </pre>
 *
 */
public final class VXCryptoNoteCliRunner {
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
	public static final class ChaCha20Poly1305Algo {
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

	/**
	 * Класс для шифрования и расшифрования данных с использованием ECIES и
	 * ChaCha20-Poly1305. Этот класс реализует механизм безопасного обмена данными,
	 * где ключи инициализации (IV) и ключи шифрования передаются с помощью ECIES
	 * (Elliptic Curve Integrated Encryption Scheme), а сами данные шифруются
	 * алгоритмом ChaCha20-Poly1305.
	 */
	public static final class ECIESChaCha20Poly1305Engine {
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
		public static InputStream decrypt(final KeyPair reciever, final InputStream source) throws IOException,
				NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

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
				final InputStream source)
				throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
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

	/**
	 * Интерфейс INettyIO предоставляет методы для чтения и записи данных в потоках
	 * ввода-вывода с использованием буферов Netty. Этот интерфейс включает
	 * утилитарные методы для работы с массивами байтов, целочисленными значениями,
	 * а также их сериализацией и десериализацией.
	 */
	interface INettyIO {
		/** Единственный экземпляр интерфейса INettyIO. */
		INettyIO INSTANCE = new INettyIO() {
		};

		/**
		 * Читает массив байтов из входного потока с заданной длиной.
		 *
		 * @param inputStream Входной поток данных.
		 * @param length      Длина массива для чтения.
		 * @return Массив байтов, прочитанных из потока.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default byte[] readArray(final InputStream inputStream, final int length) throws IOException {
			final var byteBuf = this.readBuffer(inputStream, length);
			return Objects.requireNonNull(byteBuf.array());
		}

		/**
		 * Читает массив байтов из переданного массива, используя его первую часть в
		 * качестве указателя длины.
		 *
		 * @param source Исходный массив байтов.
		 * @return Извлеченный массив байтов.
		 * @throws IOException В случае ошибки чтения.
		 */
		default byte[] readArrayByInt(final byte[] source) throws IOException {
			final var buffer = Unpooled.wrappedBuffer(source);
			final var len = buffer.readInt();
			final var array = new byte[len];
			buffer.readBytes(source);
			return array;
		}

		/**
		 * Читает массив байтов из входного потока, используя первые 4 байта в качестве
		 * указателя длины.
		 *
		 * @param source Входной поток данных.
		 * @return Извлеченный массив байтов.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default byte[] readArrayByInt(final InputStream source) throws IOException {
			final var length = this.readInt(source);
			return this.readArray(source, length);
		}

		/**
		 * Читает массив байтов из входного потока, используя первые 4 байта (в формате
		 * Little Endian) в качестве указателя длины.
		 *
		 * @param source Входной поток данных.
		 * @return Извлеченный массив байтов.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default byte[] readArrayByIntLE(final InputStream source) throws IOException {
			final var length = this.readIntLE(source);
			return this.readArray(source, length);
		}

		/**
		 * Читает буфер заданной длины из входного потока.
		 *
		 * @param inputStream Входной поток данных.
		 * @param length      Длина данных для чтения.
		 * @return Буфер с прочитанными данными.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default ByteBuf readBuffer(final InputStream inputStream, int length) throws IOException {
			final var buffer = Objects.requireNonNull(Unpooled.buffer(length, length));
			while (length != 0) {
				final var readed = buffer.writeBytes(inputStream, length);
				if (readed == 1) {
					throw new IOException("");
				}
				length -= readed;
			}
			return buffer;
		}

		/**
		 * Читает 4-байтовое целое число из входного потока.
		 *
		 * @param inputStream Входной поток данных.
		 * @return Прочитанное целое число.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default int readInt(final InputStream inputStream) throws IOException {
			return this.readBuffer(inputStream, 4).readInt();
		}

		/**
		 * Читает 4-байтовое целое число (в формате Little Endian) из входного потока.
		 *
		 * @param inputStream Входной поток данных.
		 * @return Прочитанное целое число.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default int readIntLE(final InputStream inputStream) throws IOException {
			return this.readBuffer(inputStream, 4).readIntLE();
		}

		/**
		 * Разделяет массив байтов на отдельные подмассивы, используя первые 4 байта
		 * каждого блока как указатель длины.
		 *
		 * @param source Исходный массив байтов.
		 * @return Список извлеченных массивов.
		 * @throws IOException В случае ошибки обработки данных.
		 */
		default ArrayList<byte[]> splitArray(final byte[] source) throws IOException {
			final var tmp = new ArrayList<byte[]>();
			final var buffer = Unpooled.wrappedBuffer(source);
			while (buffer.readableBytes() > 0) {
				final var len = buffer.readInt();
				if (len < 0) {
					throw new IOException();
				}
				final var array = new byte[len];
				buffer.readBytes(array);
				tmp.add(array);
			}
			return tmp;
		}

		/**
		 * Записывает массив байтов в выходной поток.
		 *
		 * @param output Выходной поток данных.
		 * @param array  Массив байтов для записи.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default void writeArray(final OutputStream output, final byte[] array) throws IOException {
			output.write(array);
		}

		/**
		 * Записывает 4-байтовое целое число в выходной поток.
		 *
		 * @param output Выходной поток данных.
		 * @param number Число для записи.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default void writeInt(final OutputStream output, final int number) throws IOException {
			final var buffer = Unpooled.buffer(4, 4);
			buffer.writeInt(number);
			output.write(buffer.array());
			buffer.release();
		}

		/**
		 * Записывает массив байтов в выходной поток, предварительно записав его длину
		 * как 4-байтовое целое число.
		 *
		 * @param output Выходной поток данных.
		 * @param array  Массив байтов для записи.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default void writeIntArray(final OutputStream output, final byte[] array) throws IOException {
			this.writeInt(output, array.length);
			output.write(array);
		}

		/**
		 * Записывает 4-байтовое целое число в выходной поток в формате Little Endian.
		 *
		 * @param output Выходной поток данных.
		 * @param number Число для записи.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default void writeIntLE(final OutputStream output, final int number) throws IOException {
			final var buffer = Unpooled.buffer(4, 4);
			buffer.writeIntLE(number);
			output.write(buffer.array());
			buffer.release();
		}

		/**
		 * Записывает массив байтов в выходной поток, предварительно записав его длину
		 * как 4-байтовое целое число в формате Little Endian.
		 *
		 * @param output Выходной поток данных.
		 * @param array  Массив байтов для записи.
		 * @throws IOException В случае ошибки ввода-вывода.
		 */
		default void writeIntLEArray(final OutputStream output, final byte[] array) throws IOException {
			this.writeIntLE(output, array.length);
			output.write(array);
		}
	}

	enum Operations {
		keyGen, keyList, keyImport, keyExport, encrypt, decrypt
	}

	/**
	 * Класс {@code SECP521R1} предоставляет методы для выполнения операций
	 * шифрования и дешифрования с использованием алгоритма ECIES (Elliptic Curve
	 * Integrated Encryption Scheme) на базе кривой SECP521R1. Класс включает
	 * утилитарные методы для шифрования и дешифрования с использованием
	 * эллиптической криптографии.
	 */
	public static final class SECP521R1 {
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
		public static byte[] encryptBytes(final PrivateKey senderPrivateKey, final PublicKey reciever,
				final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
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

	/**
	 * Класс {@code VXCertGen} предоставляет методы для генерации X.509 сертификатов
	 * с использованием ключевой пары. Он позволяет создавать сертификаты с
	 * алгоритмом SHA512withECDSA.
	 */
	public static final class VXCertGen {

		/**
		 * Генерирует X.509 сертификат на основе заданной ключевой пары.
		 *
		 * @param keyPair Ключевая пара, использующаяся для создания сертификата
		 *                (включает публичный и приватный ключи).
		 * @return Сгенерированный X.509 сертификат.
		 * @throws OperatorCreationException Если возникает ошибка при создании
		 *                                   оператора подписи.
		 * @throws CertificateException      Если возникает ошибка при создании
		 *                                   сертификата.
		 */
		public static X509Certificate genCert(final KeyPair keyPair)
				throws OperatorCreationException, CertificateException {
			final var publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
			final var now = Instant.now();
			final var after = now.plus(Duration.ofDays(1000 * 365));
			final var notBefore = Date.from(now);
			final var notAfter = Date.from(after);

			final var certBuilder = new X509v3CertificateBuilder(new X500Name("CN=Example"), BigInteger.ONE, notBefore,
					notAfter, new X500Name("CN=Example"), publicKeyInfo);

			final var signer = new JcaContentSignerBuilder("SHA512withECDSA")
					.setProvider(VXCryptoNoteCliRunner.PROVIDER).build(keyPair.getPrivate());
			final var certHolder = certBuilder.build(signer);
			return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
		}

		/**
		 * Запрещаем создание объекта этого класса
		 */
		private VXCertGen() { /* Запрещаем создание объекта этого класса */ }
	}

	/**
	 * Класс {@code VXKeyGen} предоставляет методы для генерации ключевых пар с
	 * использованием алгоритма EC (Elliptic Curve), основанного на кривой
	 * SECP521R1. Класс использует криптографические алгоритмы для генерации
	 * приватных и публичных ключей.
	 */
	public static final class VXKeyGen {

		/**
		 * Создает и инициализирует {@code KeyPairGenerator} для генерации ключевой пары
		 * на основе кривой SECP521R1.
		 *
		 * @return Инициализированный генератор ключевых пар.
		 * @throws NoSuchAlgorithmException           Если выбранный алгоритм (EC) не
		 *                                            поддерживается.
		 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
		 *                                            некорректны.
		 */
		public static KeyPairGenerator generator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
			final var generator = KeyPairGenerator.getInstance("EC", VXCryptoNoteCliRunner.PROVIDER);
			generator.initialize(new ECGenParameterSpec("secp521r1"), SecureRandom.getInstanceStrong());
			return generator;
		}

		/**
		 * Генерирует новую пару ключей (приватный и публичный ключ) с использованием
		 * алгоритма EC и кривой SECP521R1.
		 *
		 * @return Сгенерированная пара ключей.
		 * @throws NoSuchAlgorithmException           Если выбранный алгоритм (EC) не
		 *                                            поддерживается.
		 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
		 *                                            некорректны.
		 */
		public static KeyPair genKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
			return VXKeyGen.generator().generateKeyPair();
		}

		/**
		 * Запрещаем создание объекта этого класса
		 */
		private VXKeyGen() { /* Запрещаем создание объекта этого класса */ }
	}

	/**
	 * Класс {@code VXKeystore} предоставляет методы для работы с хранилищем ключей
	 * в формате BCFKS (Bouncy Castle KeyStore), позволяя загружать, сохранять и
	 * управлять ключами и сертификатами в хранилище. Использует провайдер Bouncy
	 * Castle для работы с хранилищем.
	 */
	public static final class VXKeystore {
		private final KeyStore keyStore;

		/**
		 * Создает новый объект {@code VXKeystore}, загружая хранилище ключей из
		 * указанного файла или создавая новое, если файл не существует.
		 *
		 * @param path     Путь к файлу хранилища ключей.
		 * @param password Пароль для доступа к хранилищу.
		 * @throws KeyStoreException        Если возникает ошибка при создании хранилища
		 *                                  ключей.
		 * @throws NoSuchAlgorithmException Если выбранный алгоритм не поддерживается.
		 * @throws CertificateException     Если возникает ошибка при загрузке
		 *                                  сертификатов.
		 * @throws IOException              Если возникает ошибка при чтении или записи
		 *                                  файлов.
		 */
		public VXKeystore(final Path path, final char[] password)
				throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
			this.keyStore = KeyStore.getInstance("BCFKS", VXCryptoNoteCliRunner.PROVIDER);
			if (Files.exists(path)) {
				try (var inputStream = Files.newInputStream(path)) {
					this.keyStore.load(inputStream, password);
				}
			} else {
				this.keyStore.load(null);
			}
		}

		/**
		 * Проверяет, существует ли в хранилище ключей запись с указанным псевдонимом.
		 *
		 * @param alias Псевдоним ключа.
		 * @return {@code true}, если псевдоним существует, иначе {@code false}.
		 * @throws KeyStoreException Если возникает ошибка при обращении к хранилищу.
		 */
		public boolean containsAlias(final String alias) throws KeyStoreException {
			return this.keyStore.containsAlias(alias);
		}

		/**
		 * Сохраняет текущее хранилище ключей в указанный файл.
		 *
		 * @param path     Путь к файлу, в который будет сохранено хранилище.
		 * @param password Пароль для защиты хранилища.
		 * @throws KeyStoreException        Если возникает ошибка при сохранении
		 *                                  хранилища.
		 * @throws NoSuchAlgorithmException Если выбранный алгоритм не поддерживается.
		 * @throws CertificateException     Если возникает ошибка при работе с
		 *                                  сертификатами.
		 * @throws IOException              Если возникает ошибка при записи в файл.
		 */
		public void save(final Path path, final char[] password)
				throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
			try (var outputStream = Files.newOutputStream(path)) {
				this.keyStore.store(outputStream, password);
			}
		}

		/**
		 * Добавляет новый ключ в хранилище с указанным псевдонимом и цепочкой
		 * сертификатов.
		 *
		 * @param alias    Псевдоним для ключа.
		 * @param key      Приватный ключ.
		 * @param password Пароль для защиты ключа.
		 * @param chain    Цепочка сертификатов, привязанных к ключу.
		 * @throws KeyStoreException Если возникает ошибка при добавлении ключа в
		 *                           хранилище.
		 */
		public void setKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
				throws KeyStoreException {
			this.keyStore.setKeyEntry(alias, key, password, chain);
		}

		/**
		 * Добавляет новый ключ в хранилище с указанным псевдонимом и сертификатом.
		 *
		 * @param alias       Псевдоним для ключа.
		 * @param key         Приватный ключ.
		 * @param password    Пароль для защиты ключа.
		 * @param certificate Сертификат, привязанный к ключу.
		 * @throws KeyStoreException Если возникает ошибка при добавлении ключа в
		 *                           хранилище.
		 */
		public void setKeyEntry(final String alias, final Key key, final char[] password,
				final X509Certificate certificate) throws KeyStoreException {
			this.setKeyEntry(alias, key, password, new X509Certificate[] {
					certificate
			});
		}

		/**
		 * Проверяет, существует ли в хранилище ключей запись с указанным псевдонимом и
		 * выбрасывает исключение, если псевдоним уже существует.
		 *
		 * @param alias Псевдоним ключа.
		 * @throws KeyStoreException     Если возникает ошибка при обращении к
		 *                               хранилищу.
		 * @throws IllegalStateException Если псевдоним уже существует в хранилище.
		 */
		public void throwIfExistAlias(final String alias) throws KeyStoreException {
			if (this.containsAlias(alias)) {
				throw new IllegalStateException("%s существует");
			}
		}

		/**
		 * Проверяет, существует ли в хранилище ключей запись с указанным псевдонимом и
		 * выбрасывает исключение, если псевдоним не существует.
		 *
		 * @param alias Псевдоним ключа.
		 * @throws KeyStoreException     Если возникает ошибка при обращении к
		 *                               хранилищу.
		 * @throws IllegalStateException Если псевдоним не существует в хранилище.
		 */
		public void throwIfNoExistAlias(final String alias) throws KeyStoreException {
			if (!this.containsAlias(alias)) {
				throw new IllegalStateException("%s не существует");
			}
		}
	}

	/**
	 * Провайдер криптографических алгоритмов, использующий библиотеку Bouncy
	 * Castle.
	 * <p>
	 * Этот провайдер необходим для добавления поддержки дополнительных
	 * криптографических алгоритмов, которые не поддерживаются стандартной
	 * библиотекой Java, включая шифрование, цифровые подписи, работу с
	 * сертификатами и хэширование. Bouncy Castle предоставляет расширенные
	 * возможности для безопасного выполнения криптографических операций в
	 * приложении.
	 * </p>
	 *
	 * <p>
	 * Провайдер добавляется в систему с помощью вызова
	 * {@link Security#addProvider(Provider)}, что позволяет использовать
	 * криптографические функции, реализованные в Bouncy Castle, для различных
	 * операций, таких как шифрование, дешифрование, создание и верификация
	 * подписей, работа с сертификатами и хэширование данных.
	 * </p>
	 *
	 * <p>
	 * Пример использования:
	 * </p>
	 *
	 * <pre>
	 * Security.addProvider(PROVIDER);
	 * Signature signature = Signature.getInstance("SHA256withECDSA", PROVIDER);
	 * </pre>
	 *
	 * @see BouncyCastleProvider
	 * @see Security
	 * @see Signature
	 */
	public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

	/**
	 * Выполняет расшифровку данных, используя приватный ключ из хранилища ключей, и
	 * сохраняет результат в файл.
	 *
	 * <p>
	 * Метод извлекает приватный ключ для указанного alias из хранилища ключей,
	 * после чего расшифровывает данные, используя алгоритм ECIES с
	 * ChaCha20-Poly1305. Полученные данные сохраняются в целевой файл.
	 * </p>
	 *
	 * @param args Массив строковых аргументов, в котором ожидаются следующие
	 *             параметры: 1. Путь к хранилищу ключей. 2. Строка "decrypt". 3.
	 *             Alias получателя (к которому привязан приватный ключ). 4. Путь к
	 *             исходному зашифрованному файлу. 5. Путь к целевому файлу для
	 *             расшифрованных данных.
	 * @throws IllegalArgumentException           Если количество аргументов в
	 *                                            массиве не равно 5.
	 * @throws IOException                        Если возникла ошибка при чтении
	 *                                            или записи файлов.
	 * @throws KeyStoreException                  Если возникла ошибка при работе с
	 *                                            хранилищем ключей.
	 * @throws NoSuchAlgorithmException           Если указанный алгоритм не найден.
	 * @throws CertificateException               Если возникла ошибка при работе с
	 *                                            сертификатами.
	 * @throws InvalidKeyException                Если ключ не является допустимым.
	 * @throws InvalidKeySpecException            Если спецификация ключа
	 *                                            недействительна.
	 * @throws NoSuchPaddingException             Если указанный режим шифрования не
	 *                                            существует.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма неверны.
	 * @throws IllegalBlockSizeException          Если размер блока данных неверен.
	 * @throws BadPaddingException                Если в процессе дешифрования
	 *                                            возникла ошибка с паддингом.
	 * @throws UnrecoverableKeyException          Если ключ не может быть
	 *                                            восстановлен из хранилища.
	 */
	public static void decrypt(final String[] args)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidKeyException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException {
		// keystore_0 decrypt_1 кому_2 source_3 decrypted_4
		if (args.length != 5) {
			throw new IllegalArgumentException();
		}
		final var keystorePath = Path.of(args[0]);
		final var aliasTo = args[2];
		final var sourcePath = Path.of(args[3]);
		final var targetPath = Path.of(args[4]);

		VXCryptoNoteCliRunner.throwIfNoExist(keystorePath);
		VXCryptoNoteCliRunner.throwIfNoExist(sourcePath);
		VXCryptoNoteCliRunner.throwIfExist(targetPath);

		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);
		keystore.throwIfNoExistAlias(aliasTo);

		final var receiver = VXCryptoNoteCliRunner.extractKeyPair(keystore, password, aliasTo);

		try (var inputStream = Files.newInputStream(sourcePath);) {
			final var decrypted = ECIESChaCha20Poly1305Engine.decrypt(receiver, inputStream);
			Files.copy(decrypted, targetPath);
		}
	}

	/**
	 * Выполняет шифрование данных, используя публичный ключ получателя и приватный
	 * ключ отправителя, и сохраняет результат в файл.
	 *
	 * <p>
	 * Метод извлекает приватный ключ отправителя и публичный ключ получателя из
	 * хранилища ключей, затем шифрует данные с использованием алгоритма ECIES с
	 * ChaCha20-Poly1305. Полученные зашифрованные данные сохраняются в целевой
	 * файл.
	 * </p>
	 *
	 * @param args Массив строковых аргументов, в котором ожидаются следующие
	 *             параметры: 1. Путь к хранилищу ключей. 2. Строка "encrypt". 3.
	 *             Alias отправителя (к которому привязан приватный ключ). 4. Alias
	 *             получателя (к которому привязан публичный ключ). 5. Путь к
	 *             исходным данным для шифрования. 6. Путь к целевому файлу для
	 *             зашифрованных данных.
	 * @throws IllegalArgumentException           Если количество аргументов в
	 *                                            массиве не равно 6.
	 * @throws KeyStoreException                  Если возникла ошибка при работе с
	 *                                            хранилищем ключей.
	 * @throws NoSuchAlgorithmException           Если указанный алгоритм не найден.
	 * @throws CertificateException               Если возникла ошибка при работе с
	 *                                            сертификатами.
	 * @throws IOException                        Если возникла ошибка при чтении
	 *                                            или записи файлов.
	 * @throws UnrecoverableKeyException          Если ключ не может быть
	 *                                            восстановлен из хранилища.
	 * @throws InvalidKeyException                Если ключ не является допустимым.
	 * @throws NoSuchPaddingException             Если указанный режим шифрования не
	 *                                            существует.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма неверны.
	 * @throws IllegalBlockSizeException          Если размер блока данных неверен.
	 * @throws BadPaddingException                Если в процессе шифрования
	 *                                            возникла ошибка с паддингом.
	 */
	public static void encrypt(final String[] args) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// keystore_0 encrypt_1 кто_2 кому_3 source_4 encrypted_5
		if (args.length != 6) {
			throw new IllegalArgumentException();
		}
		final var keystorePath = Path.of(args[0]);
		final var aliasWho = args[2];
		final var aliasTo = args[3];

		final var sourcePath = Path.of(args[4]);
		final var targetPath = Path.of(args[5]);

		VXCryptoNoteCliRunner.throwIfNoExist(keystorePath);
		VXCryptoNoteCliRunner.throwIfNoExist(sourcePath);
		VXCryptoNoteCliRunner.throwIfExist(targetPath);

		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);
		keystore.throwIfNoExistAlias(aliasWho);
		keystore.throwIfNoExistAlias(aliasTo);

		final var sender = VXCryptoNoteCliRunner.extractKeyPair(keystore, password, aliasWho);
		final var reciever = VXCryptoNoteCliRunner.extractPublic(keystore, aliasTo);

		try (var inputStream = Files.newInputStream(sourcePath); var outputStream = Files.newOutputStream(targetPath)) {
			ECIESChaCha20Poly1305Engine.encrypt(sender, reciever, outputStream, inputStream);
		}
	}

	/**
	 * Извлекает пару ключей (приватный и публичный) для указанного псевдонима из
	 * хранилища ключей.
	 *
	 * @param keystore Хранилище ключей {@code VXKeystore}.
	 * @param password Пароль для доступа к хранилищу.
	 * @param alias    Псевдоним ключа.
	 * @return Пара ключей, содержащая публичный и приватный ключи.
	 * @throws UnrecoverableKeyException Если не удалось извлечь приватный ключ.
	 * @throws KeyStoreException         Если возникает ошибка при доступе к
	 *                                   хранилищу ключей.
	 * @throws NoSuchAlgorithmException  Если алгоритм для извлечения ключа не
	 *                                   поддерживается.
	 * @throws CertificateException      Если цепочка сертификатов не найдена или
	 *                                   имеет неверное количество сертификатов.
	 */
	public static KeyPair extractKeyPair(final VXKeystore keystore, final char[] password, final String alias)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		final var re = keystore.keyStore;
		final var key = re.getKey(alias, password);
		if (key == null || !(key instanceof final PrivateKey privateKey)) {
			throw new UnrecoverableKeyException("Не удалось получить приватный ключ для alias: " + alias);
		}
		final var certificateChain = re.getCertificateChain(alias);
		if (certificateChain == null || certificateChain.length == 0) {
			throw new CertificateException("Цепочка сертификатов не найдена для alias: " + alias);
		}
		if (certificateChain.length != 1) {
			throw new IllegalArgumentException("должен быть 1 сертификат");
		}
		final var certificate = certificateChain[0];
		final var publicKey = certificate.getPublicKey();
		return new KeyPair(publicKey, privateKey);
	}

	/**
	 * Извлекает публичный ключ для указанного псевдонима из хранилища ключей.
	 *
	 * @param keystore Хранилище ключей {@code VXKeystore}.
	 * @param alias    Псевдоним ключа.
	 * @return Публичный ключ.
	 * @throws KeyStoreException    Если возникает ошибка при доступе к хранилищу
	 *                              ключей.
	 * @throws CertificateException Если цепочка сертификатов не найдена или имеет
	 *                              неверное количество сертификатов.
	 */
	public static PublicKey extractPublic(final VXKeystore keystore, final String alias)
			throws KeyStoreException, CertificateException {
		final var re = keystore.keyStore;
		final var certificateChain = re.getCertificateChain(alias);
		if (certificateChain == null || certificateChain.length == 0) {
			throw new CertificateException("Цепочка сертификатов не найдена для alias: " + alias);
		}
		if (certificateChain.length != 1) {
			throw new IllegalArgumentException("должен быть 1 сертификат");
		}
		final var certificate = certificateChain[0];
		return certificate.getPublicKey();
	}

	/**
	 * Экспортирует сертификат из хранилища ключей в файл.
	 *
	 * @param args Аргументы командной строки:
	 *             <ol>
	 *             <li>Путь к хранилищу ключей</li>
	 *             <li>Команда, которая должна быть "export"</li>
	 *             <li>Псевдоним ключа ({@code alias})</li>
	 *             <li>Путь к файлу для записи сертификата ({@code cert_path})</li>
	 *             </ol>
	 * @throws KeyStoreException        Если возникает ошибка при доступе к
	 *                                  хранилищу ключей.
	 * @throws NoSuchAlgorithmException Если возникает ошибка при использовании
	 *                                  алгоритма.
	 * @throws CertificateException     Если сертификат не может быть получен из
	 *                                  хранилища.
	 * @throws IOException              Если возникает ошибка ввода/вывода при
	 *                                  записи файла.
	 * @throws IllegalArgumentException Если количество аргументов командной строки
	 *                                  не соответствует ожиданиям или псевдоним не
	 *                                  существует в хранилище.
	 */
	public static void keyExport(final String[] args)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (args.length != 4) {
			throw new IllegalArgumentException("Ожидается 4 аргумента: <keystore_path> export <alias> <cert_path>");
		}
		final var keystorePath = Path.of(args[0]);
		final var alias = args[2];
		final var certPath = Path.of(args[3]);
		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);
		keystore.throwIfNoExistAlias(alias);

		// Получение сертификата из хранилища
		final var certificate = keystore.keyStore.getCertificate(alias);
		if (certificate == null) {
			throw new IllegalArgumentException("Сертификат с алиасом " + alias + " не найден в хранилище");
		}

		// Запись сертификата в файл
		try (var certStream = Files.newOutputStream(certPath)) {
			certStream.write(certificate.getEncoded());
		}
	}

	/**
	 * Генерирует пару ключей, создаёт сертификат и добавляет их в хранилище ключей.
	 *
	 * <p>
	 * Метод генерирует пару ключей (приватный и публичный), создаёт для них
	 * сертификат, а затем добавляет эти ключи и сертификат в хранилище ключей под
	 * указанным алиасом.
	 * </p>
	 *
	 * @param args Аргументы командной строки:
	 *             <ol>
	 *             <li>Путь к хранилищу ключей ({@code keystore_path})</li>
	 *             <li>Команда, которая должна быть "keyGen"</li>
	 *             <li>Псевдоним ключа ({@code alias})</li>
	 *             </ol>
	 * @throws KeyStoreException                  Если возникает ошибка при доступе
	 *                                            к хранилищу ключей.
	 * @throws NoSuchAlgorithmException           Если возникает ошибка при
	 *                                            использовании алгоритма.
	 * @throws CertificateException               Если ошибка при создании
	 *                                            сертификата.
	 * @throws IOException                        Если возникает ошибка ввода/вывода
	 *                                            при сохранении хранилища.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 * @throws OperatorCreationException          Если ошибка при создании оператора
	 *                                            для подписи сертификата.
	 * @throws IllegalArgumentException           Если количество аргументов
	 *                                            командной строки не соответствует
	 *                                            ожиданиям или псевдоним уже
	 *                                            существует в хранилище.
	 */
	public static void keyGenerate(final String[] args) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, InvalidAlgorithmParameterException, OperatorCreationException {
		if (args.length != 3) {
			throw new IllegalArgumentException("Ожидается 3 аргумента: <keystore_path> keyGen <alias>");
		}
		final var keystorePath = Path.of(args[0]);
		final var alias = args[2];
		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);
		keystore.throwIfExistAlias(alias);

		final var keys = VXKeyGen.genKeys();
		final var certificate = VXCertGen.genCert(keys);

		keystore.setKeyEntry(alias, keys.getPrivate(), password, certificate);
		keystore.save(keystorePath, password);
	}

	/**
	 * Импортирует сертификат в хранилище ключей.
	 *
	 * <p>
	 * Метод импортирует сертификат в хранилище ключей по указанному пути и
	 * добавляет его в хранилище под указанным алиасом.
	 * </p>
	 *
	 * @param args Аргументы командной строки:
	 *             <ol>
	 *             <li>Путь к хранилищу ключей ({@code keystore_path})</li>
	 *             <li>Команда, которая должна быть "import"</li>
	 *             <li>Псевдоним ключа ({@code alias})</li>
	 *             <li>Путь к файлу сертификата ({@code cert_path})</li>
	 *             </ol>
	 * @throws KeyStoreException        Если возникает ошибка при доступе к
	 *                                  хранилищу ключей.
	 * @throws NoSuchAlgorithmException Если возникает ошибка при использовании
	 *                                  алгоритма.
	 * @throws CertificateException     Если ошибка при чтении или обработке
	 *                                  сертификата.
	 * @throws IOException              Если возникает ошибка ввода/вывода при
	 *                                  чтении сертификата или сохранении хранилища.
	 * @throws IllegalArgumentException Если количество аргументов командной строки
	 *                                  не соответствует ожиданиям или псевдоним уже
	 *                                  существует в хранилище.
	 */
	public static void keyImport(final String[] args)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (args.length != 4) {
			throw new IllegalArgumentException("Ожидается 4 аргумента: <keystore_path> import <alias> <cert_path>");
		}
		final var keystorePath = Path.of(args[0]);
		final var alias = args[2];
		final var certPath = Path.of(args[3]);
		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);
		keystore.throwIfExistAlias(alias);
		// Чтение сертификата
		final var certFactory = CertificateFactory.getInstance("X.509");
		try (var certStream = Files.newInputStream(certPath)) {
			final var certificate = (X509Certificate) certFactory.generateCertificate(certStream);
			keystore.keyStore.setCertificateEntry(alias, certificate);
		}
		keystore.save(keystorePath, password);
	}

	/**
	 * Выводит список приватных ключей и цепочек сертификатов из указанного
	 * хранилища ключей (Keystore).
	 *
	 * <p>
	 * Метод ожидает один аргумент - путь к файлу хранилища ключей. Запрашивает у
	 * пользователя пароль для доступа к хранилищу через консольный ввод (скрытый).
	 * </p>
	 *
	 * <p>
	 * Выводит в консоль два списка:
	 * <ul>
	 * <li>Список приватных ключей и их алиасов.</li>
	 * <li>Список только цепочек сертификатов и их алиасов.</li>
	 * </ul>
	 *
	 *
	 * @param args массив аргументов командной строки, где args[0] - путь к файлу
	 *             хранилища ключей
	 * @throws IllegalArgumentException  если передано неверное количество
	 *                                   аргументов
	 * @throws KeyStoreException         если возникла ошибка при работе с
	 *                                   хранилищем ключей
	 * @throws NoSuchAlgorithmException  если указанный алгоритм не поддерживается
	 * @throws CertificateException      если возникает ошибка обработки сертификата
	 * @throws IOException               если возникает ошибка ввода-вывода при
	 *                                   загрузке хранилища ключей
	 * @throws UnrecoverableKeyException если ключи в хранилище не могут быть
	 *                                   восстановлены
	 */
	public static void keyList(final String[] args) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException {
		if (args.length != 2) {
			throw new IllegalArgumentException("Ожидается 1 аргумент: <keystore_path>");
		}
		final var keystorePath = Path.of(args[0]);
		final var console = System.console();
		final var password = console.readPassword("password(hide):");
		final var keystore = new VXKeystore(keystorePath, password);

		{
			final var aliases = keystore.keyStore.aliases();
			if (aliases.hasMoreElements()) {
				System.out.println("Приватные ключи и цепочки сертификатов:");
				while (aliases.hasMoreElements()) {
					final var alias = aliases.nextElement();
					if (keystore.keyStore.isKeyEntry(alias)) {
						final var certificates = keystore.keyStore.getCertificateChain(alias);
						if (certificates.length != 1) {
							throw new IllegalStateException();
						}
						System.out.println("Алиас: " + alias + " " + certificates[0]);
					}
				}
			}
		}
		{
			System.out.println();
			System.out.println("Только цепочки сертификатов:");
			final var aliases = keystore.keyStore.aliases();
			if (aliases.hasMoreElements()) {
				while (aliases.hasMoreElements()) {
					final var alias = aliases.nextElement();
					if (keystore.keyStore.isCertificateEntry(alias)) {
						final var certificate = keystore.keyStore.getCertificate(alias);
						System.out.println("Алиас: " + alias + " " + certificate);
					}
				}
			}
		}
	}

	/**
	 * Основной метод для выполнения операций с хранилищем ключей и
	 * криптографическими данными.
	 *
	 * <p>
	 * Этот метод предоставляет интерфейс командной строки для выполнения различных
	 * операций, таких как генерация ключей, шифрование, дешифрование, экспорт и
	 * импорт ключей. Когда аргументы не переданы, программа автоматически
	 * использует значения по умолчанию для выполнения операций.
	 * </p>
	 *
	 * <p>
	 * Программа поддерживает следующие операции:
	 * </p>
	 *
	 * <ul>
	 * <li><strong>keyGen</strong> - Генерация ключа и сертификата</li>
	 * <li><strong>keyList</strong> - Вывод содержимого хранилища</li>
	 * <li><strong>keyExport</strong> - Экспорт ключа в файл</li>
	 * <li><strong>keyImport</strong> - Импорт ключа из файла</li>
	 * <li><strong>decrypt</strong> - Дешифрование данных</li>
	 * <li><strong>encrypt</strong> - Шифрование данных</li>
	 * </ul>
	 *
	 * <p>
	 * Пример использования:
	 * </p>
	 *
	 * <pre>
	 * java -jar VXCryptoNoteCliRunner.jar [keystore_path] [operation] [arguments]
	 * </pre>
	 *
	 * <p>
	 * Например, для генерации ключа:
	 * </p>
	 *
	 * <pre>
	 * java -jar VXCryptoNoteCliRunner.jar keystore keyGen user1
	 * </pre>
	 *
	 * <p>
	 * Если программа вызывается без аргументов, то будет выведена справка
	 * </p>
	 *
	 * @param args Массив строковых аргументов командной строки. Ожидаются 4
	 *             аргумента для выполнения операции: 1. Путь к хранилищу ключей. 2.
	 *             Операция, которую нужно выполнить. 3. Дополнительные параметры
	 *             для выбранной операции.
	 *
	 * @throws KeyStoreException                  Если произошла ошибка при работе с
	 *                                            хранилищем ключей.
	 * @throws NoSuchAlgorithmException           Если используемый алгоритм не
	 *                                            найден.
	 * @throws CertificateException               Если произошла ошибка при работе с
	 *                                            сертификатами.
	 * @throws IOException                        Если возникла ошибка при чтении
	 *                                            или записи данных.
	 * @throws InvalidAlgorithmParameterException Если параметры алгоритма
	 *                                            некорректны.
	 * @throws OperatorCreationException          Если не удалось создать оператора
	 *                                            для подписи/шифрования.
	 * @throws UnrecoverableKeyException          Если ключ не может быть извлечён.
	 * @throws InvalidKeyException                Если ключ некорректен.
	 * @throws NoSuchPaddingException             Если не найдено необходимое
	 *                                            дополнение для шифрования.
	 * @throws IllegalBlockSizeException          Если размер блока данных
	 *                                            некорректен.
	 * @throws BadPaddingException                Если произошла ошибка при
	 *                                            обработке данных.
	 * @throws InvalidKeySpecException            Если не удаётся обработать
	 *                                            спецификацию ключа.
	 */
	public static void main(final String[] args) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, InvalidAlgorithmParameterException, OperatorCreationException,
			UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException {

		if (args.length == 0) {
			// Если аргументов нет, выводится справка по использованию
			System.out.println(
					"Использование: java -jar VXCryptoNoteCliRunner.jar <keystore_path> <operation> <arguments>");
			System.out.println("Ожидаемые операции:");
			for (final Operations op : Operations.values()) {
				System.out.println(" - " + op.name());
			}
			return;
		}

		if (args.length < 2) {
			System.err.println("Ошибка: Не указана операция для выполнения.");
			return;
		}

		Operations operation;
		try {
			operation = Operations.valueOf(args[1]);
		} catch (final Exception e) {
			System.err.println("Ошибка: Неизвестная операция '" + args[1] + "'. Доступные операции:");
			for (final Operations op : Operations.values()) {
				System.err.println(" - " + op.name());
			}
			return;
		}
		switch (operation) {
		case keyGen -> {
			VXCryptoNoteCliRunner.keyGenerate(args);
		}
		case keyList -> {
			VXCryptoNoteCliRunner.keyList(args);
		}
		case keyExport -> {
			VXCryptoNoteCliRunner.keyExport(args);
		}
		case keyImport -> {
			VXCryptoNoteCliRunner.keyImport(args);
		}
		case decrypt -> {
			VXCryptoNoteCliRunner.decrypt(args);
		}
		case encrypt -> {
			VXCryptoNoteCliRunner.encrypt(args);
		}
		default -> throw new IllegalArgumentException("Unexpected value: " + operation);
		}
	}

	/**
	 * Выбрасывает {@link NoSuchFileException}, если файл или директория уже
	 * существуют по указанному пути.
	 *
	 * <p>
	 * Метод проверяет, существует ли файл или директория по указанному пути. Если
	 * файл или директория существуют, выбрасывается исключение
	 * {@link NoSuchFileException}.
	 * </p>
	 *
	 * @param path Путь к файлу или директории.
	 * @throws NoSuchFileException Если файл или директория уже существуют по
	 *                             указанному пути.
	 */
	public static void throwIfExist(final Path path) throws NoSuchFileException {
		if (Files.exists(path)) {
			throw new NoSuchFileException(path.toString());
		}
	}

	/**
	 * Выбрасывает {@link NoSuchFileException}, если файл или директория не
	 * существуют по указанному пути.
	 *
	 * <p>
	 * Метод проверяет, существует ли файл или директория по указанному пути. Если
	 * файл или директория не существуют, выбрасывается исключение
	 * {@link NoSuchFileException}.
	 * </p>
	 *
	 * @param path Путь к файлу или директории.
	 * @throws NoSuchFileException Если файл или директория не существуют по
	 *                             указанному пути.
	 */
	public static void throwIfNoExist(final Path path) throws NoSuchFileException {
		if (Files.notExists(path)) {
			throw new NoSuchFileException(path.toString());
		}
	}

	/**
	 * Запрещаем создание объекта этого класса
	 */
	private VXCryptoNoteCliRunner() { /* Запрещаем создание экземпляров */ }
}