# VXCryptoNote CLI

VXCryptoNote CLI – это консольное приложение для работы с хранилищем ключей и криптографическими данными. Программа предоставляет возможности для генерации ключей, шифрования, дешифрования, а также экспорта и импорта ключей. При отсутствии аргументов приложение выводит справку по использованию.

## Оглавление

- [Описание](#описание)
- [Установка](#установка)
- [Использование](#использование)
- [Доступные операции](#доступные-операции)
- [Примеры использования](#примеры-использования)

## Описание

Приложение предназначено для выполнения следующих криптографических операций:

- Генерация ключа и сертификата.
- Шифрование данных.
- Дешифрование данных.
- Экспорт ключа в файл.
- Импорт ключа из файла.

Использование VXCryptoNote CLI значительно упрощает процесс работы с криптографическими операциями через командную строку.

## Установка

### Требования

- Java 23 или выше.
- Maven

### Сборка

1. Клонируйте репозиторий:
```bash
      git clone https://github.com/VigiSecTech/vigilantx-crypto-cli
```
2. Перейдите в директорию проекта:
```bash
      cd vigilantx-crypto-cli
```
3. Соберите проект с помощью Maven:
```bash
      mvn clean package
```
После успешной сборки будет создан JAR-файл, который может быть запущен через командную строку.

### Использование
Пример базового вызова приложения:
```bash
      java -jar target/vigilantx-crypto-cli-1.0-jar-with-dependencies.jar keystore_path operation arguments
```
Где:

- keystore_path – путь к хранилищу ключей.
- operation – операция, которую необходимо выполнить.
- arguments – дополнительные параметры для выбранной операции.

При отсутствии аргументов программа выводит справку с описанием доступных операций.


### Доступные операции
Приложение поддерживает следующие операции:

- keyGen: Генерация ключа и сертификата.
- keyExport: Экспорт ключа в файл.
- keyImport: Импорт ключа из файла.
- encrypt: Шифрование данных.
- decrypt: Дешифрование данных.

При неправильном указании операции приложение выведет перечень допустимых операций.


### Примеры использования

Для всех примеров ниже:

- keystore: Путь к хранилищу ключей.
- user1: алиас вашего ключа для ( генерации ||экспорта|| использования )
- user2: алиас ключа адресата ( импорта|| использования )

#### Генерация ключа
```bash
      java -jar VXCryptoNoteCliRunner.jar keystore keyGen user1
```
- user1: алиас вашего ключа для генерации

#### Экспорт ключа
```bash
      java -jar VXCryptoNoteCliRunner.jar keystore keyExport user1 user1.x509.crt
```
- user1: алиас вашего ключа для экспорта
- our.x509.crt: путь для сохранения ключа(сертификата)
#### Импорт ключа
```bash
      java -jar VXCryptoNoteCliRunner.jar keystore keyImport user2 forImport.x509.crt
```
- user2: алиас под которым сохранить ключ в хранилище
- forImport.x509.crt: путь для сохранения ключа(сертификата)

#### Шифрование данных
```bash
      java -jar VXCryptoNoteCliRunner.jar keystore encrypt user1 user2 source_file encrypted_file
```
- user1: алиас вашего ключа
- user2: алиас ключа для которого нужно шифровать
- source_file: файл, который нужно зашифровать
- encrypted_file: файл, куда сохранять

#### Дешифрование данных
```bash
      java -jar VXCryptoNoteCliRunner.jar keystore decrypt user1 encrypted_file decrypted_file
```
- user1: алиас вашего ключа
- encrypted_file: файл, который нужно дешифровать
- decrypted_file: куда сохранять расшифрованный файл
