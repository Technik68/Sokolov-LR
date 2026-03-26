using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace RsaCrypto
{
    class Program
    {
        // Размер ключа 2048 бит -> p и q по ~1024 бита (>> 2^128)
        const int KeySize = 2048;
        const string PublicKeyFile  = "public_key.xml";
        const string PrivateKeyFile = "private_key.xml";
        const string EncryptedFile  = "encrypted.bin";

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("\n=== RSA Шифрование ===");
                Console.WriteLine("1. Генерация ключей");
                Console.WriteLine("2. Шифрование текста");
                Console.WriteLine("3. Расшифровка текста");
                Console.WriteLine("0. Выход");
                Console.Write("Выбор: ");

                switch (Console.ReadLine())
                {
                    case "1": GenerateKeys(); break;
                    case "2": Encrypt();      break;
                    case "3": Decrypt();      break;
                    case "0": return;
                    default:  Console.WriteLine("Неверный выбор."); break;
                }
            }
        }

        static void GenerateKeys()
        {
            using var rsa = new RSACryptoServiceProvider(KeySize);

            // Открытый ключ (e, n) — параметры Exponent и Modulus
            string publicKey  = rsa.ToXmlString(false);
            // Закрытый ключ (d, n) — все параметры включая D
            string privateKey = rsa.ToXmlString(true);

            File.WriteAllText(PublicKeyFile,  publicKey);
            File.WriteAllText(PrivateKeyFile, privateKey);

            Console.WriteLine($"Ключи сгенерированы (размер {KeySize} бит).");
            Console.WriteLine($"Открытый ключ  -> {PublicKeyFile}");
            Console.WriteLine($"Закрытый ключ  -> {PrivateKeyFile}");
        }

        static void Encrypt()
        {
            if (!File.Exists(PublicKeyFile))
            {
                Console.WriteLine("Сначала сгенерируйте ключи (пункт 1).");
                return;
            }

            Console.Write("Введите текст для шифрования: ");
            string plainText = Console.ReadLine() ?? "";

            string publicKey = File.ReadAllText(PublicKeyFile);

            using var rsa = new RSACryptoServiceProvider(KeySize);
            rsa.FromXmlString(publicKey);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // RSA шифрует блоками; максимальный размер блока с OAEP-паддингом:
            // KeySize/8 - 42 байта
            int maxBlock = KeySize / 8 - 42;

            using var ms = new MemoryStream();

            // Записываем количество блоков (4 байта)
            int blockCount = (int)Math.Ceiling((double)plainBytes.Length / maxBlock);
            ms.Write(BitConverter.GetBytes(blockCount), 0, 4);

            for (int i = 0; i < plainBytes.Length; i += maxBlock)
            {
                int len   = Math.Min(maxBlock, plainBytes.Length - i);
                byte[] block = new byte[len];
                Array.Copy(plainBytes, i, block, 0, len);

                byte[] encrypted = rsa.Encrypt(block, true); // true = OAEP
                ms.Write(encrypted, 0, encrypted.Length);
            }

            File.WriteAllBytes(EncryptedFile, ms.ToArray());
            Console.WriteLine($"Зашифровано -> {EncryptedFile}");
        }

        static void Decrypt()
        {
            if (!File.Exists(PrivateKeyFile))
            {
                Console.WriteLine("Файл закрытого ключа не найден.");
                return;
            }

            if (!File.Exists(EncryptedFile))
            {
                Console.WriteLine("Файл зашифрованного текста не найден.");
                return;
            }

            string privateKey = File.ReadAllText(PrivateKeyFile);

            using var rsa = new RSACryptoServiceProvider(KeySize);
            rsa.FromXmlString(privateKey);

            byte[] allBytes = File.ReadAllBytes(EncryptedFile);
            int encBlockLen = KeySize / 8;
            int blockCount  = BitConverter.ToInt32(allBytes, 0);

            using var ms = new MemoryStream();

            for (int i = 0; i < blockCount; i++)
            {
                int offset = 4 + i * encBlockLen;
                byte[] block = new byte[encBlockLen];
                Array.Copy(allBytes, offset, block, 0, encBlockLen);

                byte[] decrypted = rsa.Decrypt(block, true);
                ms.Write(decrypted, 0, decrypted.Length);
            }

            string result = Encoding.UTF8.GetString(ms.ToArray());
            Console.WriteLine("Расшифрованный текст: " + result);
        }
    }
}
