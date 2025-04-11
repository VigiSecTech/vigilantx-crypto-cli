package vigilantx.crypto.apps.cryptonotecli.runner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

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