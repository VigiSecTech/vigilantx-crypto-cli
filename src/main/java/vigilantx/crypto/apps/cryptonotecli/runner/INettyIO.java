package vigilantx.crypto.apps.cryptonotecli.runner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Objects;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

/**
 * Интерфейс INettyIO предоставляет методы для чтения и записи данных в потоках
 * ввода-вывода с использованием буферов Netty. Этот интерфейс включает
 * утилитарные методы для работы с массивами байтов, целочисленными значениями,
 * а также их сериализацией и десериализацией.
 */
public interface INettyIO {
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