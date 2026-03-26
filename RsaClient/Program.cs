using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RsaClient
{
    class Program
    {
        const int    Port    = 8006;
        const string Address = "127.0.0.1";
        const int    KeySize = 2048;

        static void Main(string[] args)
        {
            // 1. Генерируем пару ключей клиента
            using var clientRsa = new RSACryptoServiceProvider(KeySize);
            string clientPublicKey = clientRsa.ToXmlString(false);
            Console.WriteLine("Клиент: ключи сгенерированы.");

            try
            {
                var socket = new Socket(AddressFamily.InterNetwork,
                                        SocketType.Stream,
                                        ProtocolType.Tcp);
                socket.Connect(new IPEndPoint(IPAddress.Parse(Address), Port));

                // 2. Отправляем серверу открытый ключ клиента
                Send(socket, Encoding.UTF8.GetBytes(clientPublicKey));
                Console.WriteLine("Открытый ключ клиента отправлен.");

                // 3. Получаем открытый ключ сервера
                byte[] serverKeyBytes = Receive(socket);
                string serverPublicKey = Encoding.UTF8.GetString(serverKeyBytes);
                Console.WriteLine("Получен открытый ключ сервера.");

                // 4. Читаем ввод, шифруем открытым ключом сервера, отправляем
                Console.Write("Введите сообщение: ");
                string message       = Console.ReadLine() ?? "";
                byte[] encrypted     = RsaEncrypt(serverPublicKey, Encoding.UTF8.GetBytes(message));
                Send(socket, encrypted);

                // 6. Получаем зашифрованный ответ, расшифровываем закрытым ключом клиента
                byte[] encryptedReply = Receive(socket);
                byte[] plainBytes     = RsaDecrypt(clientRsa, encryptedReply);
                Console.WriteLine("Ответ сервера: " + Encoding.UTF8.GetString(plainBytes));

                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Ошибка: " + ex.Message);
            }

            Console.Read();
        }

        // --- Отправка: [4 байта длина][данные] ---
        static void Send(Socket socket, byte[] data)
        {
            socket.Send(BitConverter.GetBytes(data.Length));
            socket.Send(data);
        }

        // --- Приём: читаем длину, затем все байты ---
        static byte[] Receive(Socket socket)
        {
            byte[] lenBuf = new byte[4];
            ReceiveExact(socket, lenBuf, 4);
            int len  = BitConverter.ToInt32(lenBuf, 0);
            byte[] buf = new byte[len];
            ReceiveExact(socket, buf, len);
            return buf;
        }

        static void ReceiveExact(Socket socket, byte[] buf, int count)
        {
            int received = 0;
            while (received < count)
                received += socket.Receive(buf, received, count - received, SocketFlags.None);
        }

        // --- RSA шифрование произвольных данных открытым ключом ---
        static byte[] RsaEncrypt(string publicKeyXml, byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider(KeySize);
            rsa.FromXmlString(publicKeyXml);

            int maxBlock = KeySize / 8 - 42;
            int encBlock = KeySize / 8;

            int blockCount = (int)Math.Ceiling((double)data.Length / maxBlock);
            byte[] result  = new byte[4 + blockCount * encBlock];

            BitConverter.GetBytes(blockCount).CopyTo(result, 0);

            for (int i = 0; i < blockCount; i++)
            {
                int offset = i * maxBlock;
                int len    = Math.Min(maxBlock, data.Length - offset);
                byte[] block = new byte[len];
                Array.Copy(data, offset, block, 0, len);

                byte[] enc = rsa.Encrypt(block, true);
                enc.CopyTo(result, 4 + i * encBlock);
            }
            return result;
        }

        // --- RSA расшифровка закрытым ключом ---
        static byte[] RsaDecrypt(RSACryptoServiceProvider rsa, byte[] data)
        {
            int encBlock   = KeySize / 8;
            int blockCount = BitConverter.ToInt32(data, 0);

            using var ms = new System.IO.MemoryStream();
            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[encBlock];
                Array.Copy(data, 4 + i * encBlock, block, 0, encBlock);
                byte[] dec = rsa.Decrypt(block, true);
                ms.Write(dec, 0, dec.Length);
            }
            return ms.ToArray();
        }
    }
}
