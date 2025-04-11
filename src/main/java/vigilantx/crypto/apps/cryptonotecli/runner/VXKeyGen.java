package vigilantx.crypto.apps.cryptonotecli.runner;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * Класс {@code VXKeyGen} предоставляет методы для генерации ключевых пар с
 * использованием алгоритма EC (Elliptic Curve), основанного на кривой
 * SECP521R1. Класс использует криптографические алгоритмы для генерации
 * приватных и публичных ключей.
 */
public final class VXKeyGen {

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