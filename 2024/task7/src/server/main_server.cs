using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC.Multiplier;

public class EllipticCurveServer
{
    private static FpCurve curve;
    private static Org.BouncyCastle.Math.EC.ECPoint ecPointGen;
    private static SecureRandom secureRandom;
    private static TcpListener tcpServer;
    private static NetworkStream networkStream;
    private static IStreamCipher iStreamCipher;

    static EllipticCurveServer()
    {
        //string strParamP = "c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd";
        string strEncParamP = "463F43CDC15079D91C4AB352F862D545B097C05DC765794A4F5A8BC54828DE86E7D6B7E4657348A9EF3C89711A5F226502E0627B60079931BA7878B6BB4B22A384F20484811BE84E080C73C7E87B4707AD835B1F04236ADED81F4C565839C1C4";
        string strParamP = DecodeEncryptData(strEncParamP);
        BigInteger bigIntP = new BigInteger(strParamP, 16);

        //string strParamA = "a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f";
        string strEncParamA = "443644C595002F80181FB900FE6A8445E59592549366771F4F5B8BC24E7DD7D7E182E7EA307747F9EC3ADA22195C71670CE43A7B6551CC31EF287AE0EF4921A3DCF052848041EB1904097EC2BD2B4608F482531F5223698DDD4818550A3890C6";
        string strParamA = DecodeEncryptData(strEncParamA);
        BigInteger bigIntA = new BigInteger(strParamA, 16);

        //string strParamB = "9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380";
        string strEncParamB = "1C604ACFC8012F8A1C49E950FE3CD442E3C5C258C2312A1C1C58DD901A7FD0D5E3D4EBB861214EABEC6B88204F0A74620DE4652F60049838B42F2EE2E04C70A6DCA501898041E61D585A2ECDEC784652F4D7501D57223DD9DB191D050C399F90";
        string strParamB = DecodeEncryptData(strEncParamB);
        BigInteger bigIntB = new BigInteger(strParamB, 16);

        //string strGenX = "087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8";
        string strEncGenX = "153E449EC4047A8B1C1BBD50AA3CD540B0C69458C3667F4E1B5C8B9C1A7281D6E183E7BA65244FAEEA678F22100924670CE0677F630BCD6CBB7B22B3E91E21A2DDF307898344EF4C0C582D92B82E1456A5D35A4D00256ADCD81B4F505F33C398";
        string strGenX = DecodeEncryptData(strEncGenX);
        BigInteger bigIntGenX = new BigInteger(strGenX, 16);

        //string strGenY = "127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182";
        string strEncGenY = "143444C8C3577C89194DB804AC3E8243E2C0955FC46A781C1857DEC5187B85D1E7D3E0B935241AABED6B8D22480D2E3204EE372E32039738BD7D28E5B84876F9D5A35185D043EF480E5B7BC6EC231352F380071958216CDD881D1954013B9F92";
        string strGenY = DecodeEncryptData(strEncGenY);
        BigInteger bigIntGenY = new BigInteger(strGenY, 16);

        EllipticCurveServer.curve = new FpCurve(bigIntP, bigIntA, bigIntB);

        EllipticCurveServer.ecPointGen = EllipticCurveServer.curve.CreatePoint(bigIntGenX, bigIntGenY);

        EllipticCurveServer.secureRandom = new SecureRandom();
    }

    public static void Run()
    {
        const int port = 31337;

        EllipticCurveServer.tcpServer = new TcpListener(IPAddress.Any, port);
        EllipticCurveServer.tcpServer.Start();

        int connectionCount = 0;
        while (true)
        {
            TcpClient client = null;
            try
            {
                Console.WriteLine("Waiting for connection - " + connectionCount.ToString());

                client = EllipticCurveServer.tcpServer.AcceptTcpClient();

                Console.WriteLine("Client connect.");

                EllipticCurveServer.networkStream = client.GetStream();
                EllipticCurveServer.keyExchange();
                EllipticCurveServer.SendCommand();
                Console.WriteLine("Client disconnect.");
            }
            catch (IOException ex) when (ex.InnerException is SocketException se &&
                              se.SocketErrorCode == SocketError.ConnectionReset)
            {
                Console.WriteLine("Remote host forcibly closed the connection.");
            }
            catch (IOException ex)
            {
                Console.WriteLine("Input/output error:");
                Console.WriteLine(ex.Message);

            }
            catch (SocketException ex)
            {
                Console.WriteLine("Socket error:");
                Console.WriteLine(ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An unexpected error occurred:");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                if (EllipticCurveServer.networkStream != null)
                {
                    try { EllipticCurveServer.networkStream.Close(); } catch { }
                    EllipticCurveServer.networkStream = null;
                }

                if (client != null)
                {
                    try { client.Close(); } catch { }
                }

                Console.WriteLine("Ready for the next connection...");
            }
            connectionCount++;
        }
    }

    public static string DecodeEncryptData(string inStr)
    {
        byte[] bArray = Convert.FromHexString(inStr);
        byte bKey = 0;
        int intIteration = 0;
        int intByteArrayLength = bArray.Length;

        if (intByteArrayLength > 0)
        {
            do
            {
                bKey = (byte)(13 * bKey + 0x25);
                bArray[intIteration] ^= bKey;
                intIteration++;
            }
            while (intByteArrayLength > intIteration);
        }
        return Encoding.UTF8.GetString(bArray);
    }

    public static BigInteger GeneratePrivateKey(int sizeInBits)
    {
        BigInteger bigIntRandomPrivateKey;
        do
        {
            SecureRandom secureRandom = EllipticCurveServer.secureRandom;
            bigIntRandomPrivateKey = new BigInteger(sizeInBits, secureRandom);
        }
        while (bigIntRandomPrivateKey.CompareTo(BigInteger.Zero) == 0);

        return bigIntRandomPrivateKey;
    }

    private static void keyExchange()
    {
        // string strXorKey = "133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337";
        string strEncXorKey = "143540CBC0512C8F4C4DB803F8698447E4C5905B90617C1F1C5D88934879D4D7B4D5E0EB60714CAFEC6DD8231809246704E5307B30019C3FBC7D28B3E81974F7D4F5008B8011EC4F0C0D78C3B8294407A485501B50213CDFDC1D485308399497";
        string strXorKey = EllipticCurveServer.DecodeEncryptData(strEncXorKey);
        BigInteger bigXorKey = new BigInteger(strXorKey, 16);

        if (EllipticCurveServer.ecPointGen == null || EllipticCurveServer.networkStream == null)
        {
            // string strNull = "null";
            string strEncNull = "4B731F90";
            string strNull = DecodeEncryptData(strEncNull);
            throw new InvalidOperationException(strNull);
        }

        BigInteger bigIntServerPrivateKey = EllipticCurveServer.GeneratePrivateKey(128);
        Org.BouncyCastle.Math.EC.ECPoint ecPointServerPublic = EllipticCurveServer.ecPointGen.Multiply(bigIntServerPrivateKey);
        Org.BouncyCastle.Math.EC.ECPoint ecPointServerPublicNormolized = ecPointServerPublic.Normalize();

        if (ecPointServerPublicNormolized.IsInfinity)
        {
            // string strNull = "inf";
            string strEncInf = "A4C6815";
            string strInf = DecodeEncryptData(strEncInf);
            throw new InvalidOperationException(strInf);
        }

        byte[] bArrayBuffer = new byte[48];
        EllipticCurveServer.networkStream.Read(bArrayBuffer);

        BigInteger bigIntClientXXor = new BigInteger(1, bArrayBuffer, 0, 48, true);
        BigInteger bigIntClientX = bigIntClientXXor.Xor(bigXorKey);

#if DEBUG
        Console.WriteLine("bigIntClientXXor:\t" + bigIntClientXXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntClientX:\t\t" + bigIntClientX.ToString(16).ToUpper());
#endif

        EllipticCurveServer.networkStream.Read(bArrayBuffer);
        BigInteger bigIntClientYXor = new BigInteger(1, bArrayBuffer, 0, 48, true);
        BigInteger bigIntClientY = bigIntClientYXor.Xor(bigXorKey);

#if DEBUG
        Console.WriteLine("bigIntClientYXor:\t" + bigIntClientYXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntClientY:\t\t" + bigIntClientY.ToString(16).ToUpper());
#endif

        Org.BouncyCastle.Math.EC.ECPoint ecPointClientPublicKey = EllipticCurveServer.curve.CreatePoint(bigIntClientX, bigIntClientY);
        Org.BouncyCastle.Math.EC.ECPoint ecPointClientPublicKeyNormolized = ecPointClientPublicKey.Normalize();

        BigInteger bigIntAffineServerX = ecPointServerPublicNormolized.AffineXCoord.ToBigInteger();
        BigInteger bigIntAffinServerXXor = bigIntAffineServerX.Xor(bigXorKey);
        byte[] bArrayServerXXor = bigIntAffinServerXXor.ToByteArrayUnsigned();
        EllipticCurveServer.networkStream.Write(bArrayServerXXor);

#if DEBUG
        Console.WriteLine("bigIntServerXXor:\t" + bigIntAffinServerXXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntServerX:\t\t" + bigIntAffineServerX.ToString(16).ToUpper());
#endif

        BigInteger bigIntAffineServerY = ecPointServerPublicNormolized.AffineYCoord.ToBigInteger();
        BigInteger bigIntServerYXor = bigIntAffineServerY.Xor(bigXorKey);
        byte[] bArrayServerYXor = bigIntServerYXor.ToByteArrayUnsigned();
        EllipticCurveServer.networkStream.Write(bArrayServerYXor);

#if DEBUG
        Console.WriteLine("bigIntServerYXor:\t" + bigIntServerYXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntServerY:\t\t" + bigIntAffineServerY.ToString(16).ToUpper());
#endif

        Org.BouncyCastle.Math.EC.ECPoint ecPointSharedSecret = ecPointClientPublicKeyNormolized.Multiply(bigIntServerPrivateKey).Normalize();
        BigInteger bigIntSharedSecret = ecPointSharedSecret.AffineXCoord.ToBigInteger();
        byte[] arrayByteSharedSecret = bigIntSharedSecret.ToByteArray();
        byte[] bArrayHashSHA512 = SHA512.HashData(arrayByteSharedSecret);

        byte[] bArrayKey = new byte[32];
        Array.Copy(bArrayHashSHA512, bArrayKey, 32);

        byte[] bArrayIV = new byte[8];
        Array.Copy(bArrayHashSHA512, 32, bArrayIV, 0, 8);

        KeyParameter paramsKey = new KeyParameter(bArrayKey);
        ParametersWithIV paramsIv = new ParametersWithIV(paramsKey, bArrayIV);
        EllipticCurveServer.iStreamCipher = new ChaChaEngine(20);
        EllipticCurveServer.iStreamCipher.Init(true, paramsIv);

        // string strVerify = "verify";
        string strEncVerify = "53630195971b";
        string strVerify = EllipticCurveServer.DecodeEncryptData(strEncVerify);

        SendAndEncrypt(strVerify);

        string strReceived = ReceiveDecrypted();
        if (!strReceived.Equals(strVerify))
        {
            // string strnVerifyFailed = "verify failed";
            string strnEncVerifyFailed = "53630195971b3fde1c17e751ad";
            string strnVerifyFailed = EllipticCurveServer.DecodeEncryptData(strnEncVerifyFailed);
            throw new InvalidOperationException(strnVerifyFailed);
        }
#if DEBUG
        else
        { 
            Console.WriteLine("Right key exchange.");
        }
#endif
    }

    private static string ReceiveDecrypted()
    {
        byte[] buffer = new byte[1024];
        byte[] receivedByte = new byte[1];
        byte[] decryptedByte = new byte[1];
        int readIterations = 0;

        while (true)
        {
            ReadFromNetworkStream(EllipticCurveServer.networkStream, receivedByte, 1);
            decryptedByte[0] = EllipticCurveServer.iStreamCipher.ReturnByte(receivedByte[0]);
            if (decryptedByte[0] == 0)
            {
                break;
            }

            buffer[readIterations++] = decryptedByte[0];
            if (readIterations >= 1024)
            {
                // string strTooLong = "too long"
                string strEncTooLong = "51691cdc9d0d71df";
                string strTooLong = EllipticCurveServer.DecodeEncryptData(strEncTooLong);
                throw new InvalidOperationException(strTooLong);
            }
        }

#if DEBUG
        string strOut = Encoding.ASCII.GetString(buffer, 0, readIterations);
        if (strOut != null && strOut.Length != 0)
        {
            Console.WriteLine("=====================================================================");
            Console.WriteLine("Received data:");
            Console.WriteLine(strOut);
        }
#endif
        return Encoding.ASCII.GetString(buffer, 0, readIterations);
    }

    static int ReadFromNetworkStream(NetworkStream networkStream, byte[] buffer, int bytesToRead)
    {
        int totalBytesRead = 0;
        int receivedBytes = 0;

        while (true)
        {
            receivedBytes = networkStream.Read(buffer);
            totalBytesRead += receivedBytes;

            if (receivedBytes == 0)
                break;

            if (totalBytesRead >= bytesToRead)
                return totalBytesRead;
        }

        return totalBytesRead;
    }

    static void SendAndEncrypt(string inStrForSend)
    {
        byte[] byteArray = new byte[inStrForSend.Length + 1];
        byte[] byteArrayTemp = Encoding.UTF8.GetBytes(inStrForSend);
        byte[] byteArrayEncSend = new byte[byteArray.Length];

        int iteration = 0;

        Array.Copy(byteArrayTemp, byteArray, byteArrayTemp.Length);

        while (byteArray.Length > iteration)
        {
            byteArrayEncSend[iteration] = EllipticCurveServer.iStreamCipher.ReturnByte(byteArray[iteration]);
            iteration++;
        }
        EllipticCurveServer.networkStream.Write(byteArrayEncSend);
#if DEBUG
        if (inStrForSend != null && inStrForSend.Length != 0)
        {
            Console.WriteLine("=====================================================================");
            Console.WriteLine("Send data:");
            Console.WriteLine(inStrForSend);
        }
#endif
    }

    static int SendCommand()
    {
        string strReceived;
        string strComand;

        // string strLS = "ls";
        string strEncLS = "4975";
        string strLS = EllipticCurveServer.DecodeEncryptData(strEncLS);

        strComand = strLS;
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "cd|secrets";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = strLS;
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "cd|super secrets";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = strLS;
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "cd|.hidden";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = strLS;
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "cd|wait dot folders aren't hidden on windows";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = strLS;
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "cat|flag.txt";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();

        strComand = "exit";
        SendAndEncrypt(strComand);
        strReceived = ReceiveDecrypted();
        return 1;
    }
}

internal class main_server
{
    static void Main(string[] args)
    {
        EllipticCurveServer.Run();
    }
}
