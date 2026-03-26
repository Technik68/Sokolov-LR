using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RsaServer
{
    class Program
    {
        const int Port    = 8006;
        const int KeySize = 2048;

        static void Main(string[] args)
        {
            // 1. Генерируем пару ключей сервера
            using var serverRsa = new RSACryptoServiceProvider(KeySize);
            string serverPublicKey = serverRsa.ToXmlString(false);
            Console.WriteLine("Сервер: ключи сгенерированы.");

            var ipPoint     = new IPEndPoint(IPAddress.Parse("127.0.0.1"), Port);
            var listenSocket = new Socket(AddressFamily.InterNetwork,
                                          SocketType.Stream,
                                          ProtocolType.Tcp);
            listenSocket.Bind(ipPoint);
            listenSocket.Listen(10);
            Console.WriteLine("Сервер запущен. Ожидание подключений...");

            while (true)
            {
                Socket handler = listenSocket.Accept();
                try
                {
                    // 2. Получаем открытый ключ клиента
                    byte[] clientKeyBytes = Receive(handler);
                    string clientPublicKey = Encoding.UTF8.GetString(clientKeyBytes);
                    Console.WriteLine("Получен открытый ключ клиента.");

                    // 3. Отправляем открытый ключ сервера
                    Send(handler, Encoding.UTF8.GetBytes(serverPublicKey));
                    Console.WriteLine("Открытый ключ сервера отправлен.");

                    // 5. Получаем зашифрованное сообщение, расшифровываем
                    byte[] encryptedMsg = Receive(handler);
                    byte[] plainBytes   = RsaDecrypt(serverRsa, encryptedMsg);
                    string message      = Encoding.UTF8.GetString(plainBytes);
                    Console.WriteLine($"{DateTime.Now.ToShortTimeString()}: {message}");

                    // 5. Шифруем ответ открытым ключом клиента и отправляем
                    string reply        = "ваше сообщение доставлено";
                    byte[] encryptedReply = RsaEncrypt(clientPublicKey, Encoding.UTF8.GetBytes(reply));
                    Send(handler, encryptedReply);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Ошибка: " + ex.Message);
                }
                finally
                {
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }
            }
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

            int maxBlock = KeySize / 8 - 42; // макс. байт открытого текста на блок (OAEP)
            int encBlock = KeySize / 8;       // размер зашифрованного блока

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
