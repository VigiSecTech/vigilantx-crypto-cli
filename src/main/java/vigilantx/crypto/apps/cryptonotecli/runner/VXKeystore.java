package vigilantx.crypto.apps.cryptonotecli.runner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Класс {@code VXKeystore} предоставляет методы для работы с хранилищем ключей
 * в формате BCFKS (Bouncy Castle KeyStore), позволяя загружать, сохранять и
 * управлять ключами и сертификатами в хранилище. Использует провайдер Bouncy
 * Castle для работы с хранилищем.
 */
public final class VXKeystore {
	final KeyStore keyStore;

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
	public void setKeyEntry(final String alias, final Key key, final char[] password, final X509Certificate certificate)
			throws KeyStoreException {
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