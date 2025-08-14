using System;
using System.Threading.Tasks;
using System.Management;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;


class Program
{
    static async Task Main(string[] args)
    {
        /*  API anahtarı tanımı ve kontrolü, NVD API erişimi için gerekli. Daha güvenli kullanım için çevresel değişkenlerden alınabilir.   */
        string? apiKey = "f303e6f4-69f0-4a8b-9a1f-dbbe0f86f535";
        if (string.IsNullOrEmpty(apiKey))
        {
            Console.WriteLine("[HATA] API Anahtarı tanımlanmamış!");
            Console.WriteLine("Çıkmak için bir tuşa basın.");
            Console.ReadKey();
            return;
        }

        var checker = new CVEChecker(apiKey);

        string dbPath = args?.Length > 0 ? args[0] : "cpe_db.json";
        Console.WriteLine($"[INFO] CPE veritabanı yükleniyor: {dbPath}");
        var cpeMatcher = new CPEMatcher(dbPath);
        if (!cpeMatcher.IsInitialized)
        {
            Console.WriteLine("[HATA] CPE eşleştirici başlatılamadı. Program sonlandırılıyor.");
            return;
        }

        Console.WriteLine("\n[INFO] Kurulu yazılımlar taranıyor...");

        try
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product");
            var installedApps = searcher.Get();

            foreach (ManagementObject obj in installedApps)
            {
                string name = obj["Name"]?.ToString() ?? "Bilinmeyen";
                string version = obj["Version"]?.ToString() ?? "N/A";

                if (string.IsNullOrWhiteSpace(name) || name == "Bilinmeyen") continue;

                Console.WriteLine($"\n══════════════════════════════════════════════════════════════");
                Console.WriteLine($" UYGULAMA: {name} (Versiyon: {version})");
                Console.WriteLine($"══════════════════════════════════════════════════════════════");

                // Versiyon bilgisi, eşleştirme doğruluğunu artırmak için kullanılır.
                string? cpe = cpeMatcher.FindBestCPE(name, version, enableDebug: true, useHardcodedFallback: false);
                bool cveFound = false;

                if (!string.IsNullOrEmpty(cpe))
                {
                    Console.WriteLine($"[INFO] Güvenilir CPE eşleşmesi bulundu: {cpe}");
                    cveFound = await SearchCVEsByCPE(checker, cpe);
                }
                else
                {
                    Console.WriteLine($"[INFO] Bu uygulama için güvenilir bir CPE eşleşmesi bulunamadı.");
                }

                if (!cveFound)
                {
                    Console.WriteLine("[INFO] Yedek stratejiye geçiliyor: Anahtar kelime ile CVE aranıyor.");
                    cveFound = await SearchCVEsByKeywordFallback(checker, name);
                }

                if (!cveFound)
                {
                    Console.WriteLine("  [SONUÇ] Bu uygulama için bilinen bir zafiyet (CVE) bulunamadı.");
                }
                
                // NVD API hız limitlerine takılmamak için bekleme süresi.
                await Task.Delay(2000);
            }
        }
        catch (ManagementException ex)
        {
            Console.WriteLine($"[HATA] WMI sorgusu başarısız oldu: {ex.Message}");
            Console.WriteLine("[INFO] Program yönetici olarak çalıştırılmayı gerektiriyor olabilir.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] Beklenmedik bir hata oluştu: {ex.Message}");
        }

        Console.WriteLine("\nTarama tamamlandı!");
        Console.WriteLine("Çıkmak için bir tuşa basın.");
        Console.ReadKey();
    }



    private static async Task<bool> SearchCVEsByCPE(CVEChecker checker, string cpe)
    {
        string? jsonByCpe = await checker.GetCVEsByCPEAsync(cpe);
        if (!string.IsNullOrEmpty(jsonByCpe))
        {
            var cveList = CVEParser.ParseCVEInfo(jsonByCpe);
            if (cveList.Any())
            {
                DisplayCVEResults(cveList, $"CPE ({cpe})");
                return true;
            }
        }
        return false;
    }

    private static async Task<bool> SearchCVEsByKeywordFallback(CVEChecker checker, string programName)
    {
        string cleanedName = CPEMatcher.CleanProgramNameForSearch(programName);
        
        Console.WriteLine($"[FALLBACK] Temizlenmiş anahtar kelime ile arama: '{cleanedName}'");
        string? json = await checker.GetCVEsAsync(cleanedName);
        if (!string.IsNullOrEmpty(json))
        {
            var cveList = CVEParser.ParseCVEInfo(json);
            if (cveList.Any())
            {
                DisplayCVEResults(cveList, $"Keyword ({cleanedName})");
                return true;
            }
        }
        return false;
    }

    private static void DisplayCVEResults(List<CVEInfo> cveList, string source)
    {
        Console.WriteLine($"  [{source}] {cveList.Count} CVE bulundu:");
        
        var critical = cveList.Where(c => c.Severity == "CRITICAL").ToList();
        var high = cveList.Where(c => c.Severity == "HIGH").ToList();
        var medium = cveList.Where(c => c.Severity == "MEDIUM").ToList();
        var low = cveList.Where(c => c.Severity == "LOW").ToList();

        Action<List<CVEInfo>, string> displayGroup = (group, level) =>
        {
            if (group.Any())
            {
                Console.WriteLine($"    {level} ({group.Count} CVE):");
                foreach (var cve in group.Take(3))
                {
                    string descShort = cve.Description.Length > 120 ? cve.Description.Substring(0, 120) + "..." : cve.Description;
                    Console.WriteLine($"      → {cve.Id} (CVSS: {cve.CVSS:F1}) - {descShort}");
                }
                if (group.Count > 3) Console.WriteLine($"      → ... ve {group.Count - 3} tane daha.");
            }
        };

        displayGroup(critical, "KRİTİK SEVİYE");
        displayGroup(high, "YÜKSEK SEVİYE");
        displayGroup(medium, "ORTA SEVİYE");

        if (low.Any())
        {
            Console.WriteLine($"DÜŞÜK SEVİYE: {low.Count} CVE (detaylar gösterilmiyor)");
        }
    }
}

