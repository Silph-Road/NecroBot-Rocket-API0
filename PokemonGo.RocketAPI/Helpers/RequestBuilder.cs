using Google.Protobuf;
using PokemonGo.RocketAPI.Enums;
using POGOProtos.Networking.Envelopes;
using POGOProtos.Networking.Requests;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using PokemonGo.RocketAPI.Extensions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PokemonGo.RocketAPI.Helpers
{
    public class RequestBuilder
    {
        private readonly string _authToken;
        private readonly AuthType _authType;
        private readonly double _latitude;
        private readonly double _longitude;
        private readonly double _altitude;
        private readonly AuthTicket _authTicket;
        private readonly DateTime _startTime = DateTime.UtcNow;
        private ulong _nextRequestId;
        static private readonly Stopwatch _internalWatch = new Stopwatch();
        private readonly ISettings settings;

        public RequestBuilder(string authToken, AuthType authType, double latitude, double longitude, double altitude, ISettings settings, AuthTicket authTicket = null)
        {
            _authToken = authToken;
            _authType = authType;
            _latitude = latitude;
            _longitude = longitude;
            _altitude = altitude;
            this.settings = settings;
            _authTicket = authTicket;
            _nextRequestId = Convert.ToUInt64(RandomDevice.NextDouble() * Math.Pow(10, 18));
            if (!_internalWatch.IsRunning)
                _internalWatch.Start();

            if (encryptNative == null)
                encryptNative = (EncryptDelegate)FunctionLoader.LoadFunction<EncryptDelegate>(@"Resources\encrypt.dll", "encrypt");
        }

        private Unknown6 GenerateSignature(IEnumerable<IMessage> requests)
        {
            var ticketBytes = _authTicket.ToByteArray();

            var sig = new Signature()
            {
                LocationHash1 = Utils.GenerateLocation1(ticketBytes, _latitude, _longitude, _altitude),
                LocationHash2 = Utils.GenerateLocation2(_latitude, _longitude, _altitude),
                SensorInfo = new Signature.Types.SensorInfo()
                {
                    AccelNormalizedZ = GenRandom(9.8),
                    AccelNormalizedX = GenRandom(0.02),
                    AccelNormalizedY = GenRandom(0.3),
                    TimestampSnapshot = (ulong)_internalWatch.ElapsedMilliseconds - 230,
                    MagnetometerX = GenRandom(0.12271042913198471),
                    MagnetometerY = GenRandom(-0.015570580959320068),
                    MagnetometerZ = GenRandom(0.010850906372070313),
                    AngleNormalizedX = GenRandom(17.950439453125),
                    AngleNormalizedY = GenRandom(-23.36273193359375),
                    AngleNormalizedZ = GenRandom(-48.8250732421875),
                    AccelRawX = GenRandom(-0.0120010357350111),
                    AccelRawY = GenRandom(-0.04214850440621376),
                    AccelRawZ = GenRandom(0.94571763277053833),
                    GyroscopeRawX = GenRandom(7.62939453125e-005),
                    GyroscopeRawY = GenRandom(-0.00054931640625),
                    GyroscopeRawZ = GenRandom(0.0024566650390625),
                    AccelerometerAxes = 3
                },
                DeviceInfo = new Signature.Types.DeviceInfo()
                {
                    DeviceId = settings.DeviceId,
                    AndroidBoardName = settings.AndroidBoardName,
                    AndroidBootloader = settings.AndroidBootloader,
                    DeviceBrand = settings.DeviceBrand,
                    DeviceModel = settings.DeviceModel,
                    DeviceModelIdentifier = settings.DeviceModelIdentifier,
                    DeviceModelBoot = settings.DeviceModelBoot,
                    HardwareManufacturer = settings.HardwareManufacturer,
                    HardwareModel = settings.HardwareModel,
                    FirmwareBrand = settings.FirmwareBrand,
                    FirmwareTags = settings.FirmwareTags,
                    FirmwareType = settings.FirmwareType,
                    FirmwareFingerprint = settings.FirmwareFingerprint
                }
            };

            sig.LocationFix.Add(new Signature.Types.LocationFix()
            {
                Provider = "network",
                Latitude = (float)_latitude,
                Longitude = (float)_longitude,
                Altitude = (float)_altitude,
                //HorizontalAccuracy = (float)Math.Round(GenRandom(50, 250), 7),
                //VerticalAccuracy = RandomDevice.Next(2, 5),
                TimestampSnapshot = (ulong)_internalWatch.ElapsedMilliseconds - 200,
                //ProviderStatus = 3,
                Floor = 3,
                LocationType = 1
            });

            foreach (var request in requests)
                sig.RequestHash.Add(Utils.GenerateRequestHash(ticketBytes, request.ToByteArray()));

            byte[] _sessionHash = new byte[16];
            RandomDevice.NextBytes(_sessionHash);

            sig.SessionHash = ByteString.CopyFrom(_sessionHash);
            sig.Unknown25 = BitConverter.ToUInt32(new System.Data.HashFunction.xxHash(64, 0x88533787).ComputeHash(System.Text.Encoding.ASCII.GetBytes("\"b8fa9757195897aae92c53dbcf8a60fb3d86d745\"")), 0);

            Unknown6 val = new Unknown6()
            {
                RequestType = 6,
                Unknown2 = new Unknown6.Types.Unknown2()
                {
                    EncryptedSignature = ByteString.CopyFrom(Encrypt(sig.ToByteArray()))
                }
            };

            return val;
        }

        private static byte[] GetURandom(int size)
        {
            var rng = new RNGCryptoServiceProvider();
            var buffer = new byte[size];
            rng.GetBytes(buffer);
            return buffer;
        }

        private byte[] Encrypt(byte[] bytes)
        {
            var outputLength = 32 + bytes.Length + (256 - (bytes.Length % 256));
            var ptr = Marshal.AllocHGlobal(outputLength);
            var ptrOutput = Marshal.AllocHGlobal(outputLength);
            FillMemory(ptr, (uint)outputLength, 0);
            FillMemory(ptrOutput, (uint)outputLength, 0);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);

            var iv = GetURandom(32);
            var iv_ptr = Marshal.AllocHGlobal(iv.Length);
            Marshal.Copy(iv, 0, iv_ptr, iv.Length);

            try
            {
                var outputSize = outputLength;
                encryptNative(ptr, bytes.Length, iv_ptr, iv.Length, ptrOutput, out outputSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            var output = new byte[outputLength];
            Marshal.Copy(ptrOutput, output, 0, outputLength);
            return output;
        }

        static class FunctionLoader
        {
            [DllImport("Kernel32.dll")]
            private static extern IntPtr LoadLibrary(string path);

            [DllImport("Kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            public static Delegate LoadFunction<T>(string dllPath, string functionName)
            {
                var hModule = LoadLibrary(dllPath);
                var functionAddress = GetProcAddress(hModule, functionName);
                return Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(T));
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private unsafe delegate int EncryptDelegate(IntPtr arr, int length, IntPtr iv, int ivsize, IntPtr output, out int outputSize);

        private static EncryptDelegate encryptNative;

        [DllImport("kernel32.dll", EntryPoint = "RtlFillMemory", SetLastError = false)]
        static extern void FillMemory(IntPtr destination, uint length, byte fill);

        public RequestEnvelope GetRequestEnvelope(params Request[] customRequests)
        {
            var e = new RequestEnvelope
            {
                StatusCode = 2, //1

                RequestId = _nextRequestId++, //3
                Requests = { customRequests }, //4

                //Unknown6 = , //6
                Latitude = _latitude, //7
                Longitude = _longitude, //8
                Altitude = _altitude, //9
                AuthTicket = _authTicket, //11
                Unknown12 = 989 //12
            };
            e.Unknown6 = GenerateSignature(customRequests);
            return e;
        }

        public RequestEnvelope GetInitialRequestEnvelope(params Request[] customRequests)
        {
            var e = new RequestEnvelope
            {
                StatusCode = 2, //1

                RequestId = _nextRequestId++, //3
                Requests = { customRequests }, //4

                //Unknown6 = , //6
                Latitude = _latitude, //7
                Longitude = _longitude, //8
                Altitude = _altitude, //9
                AuthInfo = new RequestEnvelope.Types.AuthInfo
                {
                    Provider = _authType == AuthType.Google ? "google" : "ptc",
                    Token = new RequestEnvelope.Types.AuthInfo.Types.JWT
                    {
                        Contents = _authToken,
                        Unknown2 = 14
                    }
                }, //10
                Unknown12 = 989 //12
            };
            return e;
        }

        public RequestEnvelope GetRequestEnvelope(RequestType type, IMessage message)
        {
            return GetRequestEnvelope(new Request()
            {
                RequestType = type,
                RequestMessage = message.ToByteString()
            });

        }

        private static readonly Random RandomDevice = new Random();

        public static double GenRandom(double num)
        {
            var randomFactor = 0.3f;
            var randomMin = (num * (1 - randomFactor));
            var randomMax = (num * (1 + randomFactor));
            var randomizedDelay = RandomDevice.NextDouble() * (randomMax - randomMin) + randomMin; ;
            return randomizedDelay; ;
        }

        public static double GenRandom(double min, double max)
        {
            return RandomDevice.NextDouble() * (min - min) + min;
        }
    }
}