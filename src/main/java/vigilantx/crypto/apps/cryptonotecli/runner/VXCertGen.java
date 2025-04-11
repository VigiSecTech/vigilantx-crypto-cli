package vigilantx.crypto.apps.cryptonotecli.runner;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Класс {@code VXCertGen} предоставляет методы для генерации X.509 сертификатов
 * с использованием ключевой пары. Он позволяет создавать сертификаты с
 * алгоритмом SHA512withECDSA.
 */
public final class VXCertGen {

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

		final var signer = new JcaContentSignerBuilder("SHA512withECDSA").setProvider(VXCryptoNoteCliRunner.PROVIDER)
				.build(keyPair.getPrivate());
		final var certHolder = certBuilder.build(signer);
		return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
	}

	/**
	 * Запрещаем создание объекта этого класса
	 */
	private VXCertGen() { /* Запрещаем создание объекта этого класса */ }
}