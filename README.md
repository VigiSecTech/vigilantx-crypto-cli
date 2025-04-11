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
- Просмотр списка ключей и сертификатов.
- Экспорт ключа в файл.
- Импорт ключа из файла.
- Шифрование данных.
- Дешифрование данных.

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

#### Просмотр списка ключей и сертификатов
```bash
java -jar target/vigilantx-crypto-cli-1.0-jar-with-dependencies.jar keystore keyList
```
После ввода пароля программа выведет список приватных ключей и сертификатов, например:

```
password(hide):
Приватные ключи и цепочки сертификатов:
Алиас: own   [0]         Version: 3
         SerialNumber: 1
             IssuerDN: CN=Example
           Start Date: Fri Apr 11 06:54:31 UTC 2025
           Final Date: Thu Aug 12 06:54:31 UTC 3024
            SubjectDN: CN=Example
           Public Key: EC Public Key [41:c0:32:44:b3:dc:fe:be:7e:23:eb:5a:c9:6c:17:74:64:0c:c3:e0]
            X: 1bb2bbd93ff1765f44c9dac005d5f2354bd76f1b4e6ad3bd81b84a88a06387096c862ef9986ff7953eb395e82ff79295cb6c2f305c559a5b8a7ff95126a50ca462f
            Y: 99402e4edc34af3e162792d8604f6a84425359e6adcfc95d3c97c1cc659b7ef3e88fbc71d0eae869ee00d739d7f15dd80fffe24d7ba09c75cab33d3646bb9e80c7

  Signature Algorithm: SHA512withECDSA
            Signature: 308187024200d403ad4bebeff51f4e46d7638106
                       cf3691d6ba74e3ff1aa584b80f03c9042685f0cb
                       921e2eed86765ef9a05334bc81e2d12a4d80dda2
                       9853ef8004a9ec3822615c024173ddf94355d025
                       4fd7c749057ebb0191d3fcfd069ead66b1df801f
                       1e8ba267ba92004d1fa438cbe1282a6b579f9e90
                       7d3e1bc624ab0c4ceba6d1d6632869fedd85


Только цепочки сертификатов:
Алиас: other   [0]         Version: 3
         SerialNumber: 1
             IssuerDN: CN=Example
           Start Date: Fri Apr 11 06:55:16 UTC 2025
           Final Date: Thu Aug 12 06:55:16 UTC 3024
            SubjectDN: CN=Example
           Public Key: EC Public Key [38:2f:f6:1c:36:03:1d:de:8f:95:2a:df:6b:ef:f7:b9:54:18:81:57]
            X: 8673a5a51cbaeaaadbfaaf86c95a399ef78a79f8a862f30b5b155d6865f7d7c4249db325a57bb3fdcb7d2f438cee1677963f64124773b12da30b6280ec30626ce9
            Y: 16c6e57aeda242c6d18f385a27085ffaaca458249b739c50d8c8e6c8ef793c9b7c8e8d1f6834d96c7d122b4e045c79b4f16539db65010f622b98d7a42814819563e

  Signature Algorithm: SHA512withECDSA
            Signature: 30818802420105b4c34ad837fd30c8c8252ba403
                       ab32ea342d030eebe7ed8e423b914fcf1912aa58
                       249966607942621c73ff153c802aaeadb2c8949e
                       777f9506f93dcf56b866f102420182fa2b324679
                       d3dbf02041b103548c7cfde681335a1a3b236b0e
                       2bc95abc8ba9b6047f57b3e14efcba03b318df2f
                       bb563ff3eef941fbb2d6f0be18f60e9caab98d


```


#### Экспорт ключа
```bash
java -jar VXCryptoNoteCliRunner.jar keystore keyExport user1 user1.x509.crt
```
- user1: алиас вашего ключа для экспорта
- user1.x509.crt: путь для сохранения ключа(сертификата)
#### Импорт ключа
```bash
java -jar VXCryptoNoteCliRunner.jar keystore keyImport user2 user2.x509.crt
```
- user2: алиас под которым сохранить ключ в хранилище
- user2.x509.crt: путь для чтения ключа(сертификата)

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
