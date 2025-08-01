using System;
using System.Threading.Tasks;
using System.Management;

class Program
{
    static async Task Main(string[] args)
    {
        string apiKey = "f303e6f4-69f0-4a8b-9a1f-dbbe0f86f535";
        var checker = new CVEChecker(apiKey);
        
        Console.WriteLine("CPE veritabanı yükleniyor.");
        var cpeMatcher = new CPEMatcher("cpe_db.json");
        
        Console.WriteLine("Kurulu yazılımlar taranıyor.\n");

        var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product");

        foreach (ManagementObject obj in searcher.Get())
        {
            string name = obj["Name"]?.ToString() ?? "Bilinmeyen";
            string version = obj["Version"]?.ToString() ?? "N/A";

            if (!string.IsNullOrWhiteSpace(name))
            {
                Console.WriteLine($"\n=== Uygulama: {name} ({version}) ===");

                //CPE eşleştirmesi yapıyor
                string? cpe = cpeMatcher.FindBestCPE(name);
                
                if (cpe != null)
                {
                    Console.WriteLine($"CPE Eşleşmesi: {cpe}"); //eşleştirdiği CPE'yi gösterir
                    
                    //CPE ile CVE araması yapıyor
                    string cpeProduct = ExtractProductFromCPE(cpe);
                    if (!string.IsNullOrEmpty(cpeProduct))
                    {
                        Console.WriteLine($"CPE ürün adı ile CVE araması. {cpeProduct}");
                        string json = await checker.GetCVEsAsync(cpeProduct);
                        
                        if (!string.IsNullOrEmpty(json))
                        {
                            var cveList = CVEParser.ParseCVEInfo(json);
                            DisplayCVEResults(cveList, "CPE-based");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("CPE eşleşmesi bulunamadı");
                }

                //Alternatif olarak orijinal isimle de arıyor
                Console.WriteLine($"Orijinal isim ile CVE araması.");
                string cleanedName = CleanProgramName(name);
                string jsonFallback = await checker.GetCVEsAsync(cleanedName);

                if (!string.IsNullOrEmpty(jsonFallback))
                {
                    var cveListFallback = CVEParser.ParseCVEInfo(jsonFallback);
                    DisplayCVEResults(cveListFallback, "Fallback");
                }

                Console.WriteLine(new string('-', 80));
                await Task.Delay(2000); // Rate limit için bekleme ayarlanıyor
            }
        }
        
        Console.WriteLine("\nTarama tamamlandı!");
        Console.WriteLine("Çıkmak için bir tuşa basın.");
        Console.ReadKey();
    }

    private static string CleanProgramName(string name)
    {
        string cleaned = System.Text.RegularExpressions.Regex.Replace(name, 
            @"\([^)]*\)", "").Trim();
        
        string[] parts = cleaned.Split(' ');
        if (parts.Length > 2)
        {
            cleaned = string.Join(" ", parts[0], parts[1]);
        }
        
        return cleaned;
    }

    private static string ExtractProductFromCPE(string cpe)
    {
        try
        {
            // CPE formatı: cpe:2.3:a:vendor:product:version
            var parts = cpe.Split(':');
            if (parts.Length >= 5)
            {
                string vendor = parts[3].Replace("_", " ");
                string product = parts[4].Replace("_", " ");
                
                if (!string.IsNullOrEmpty(vendor) && !string.IsNullOrEmpty(product))
                {
                    return $"{vendor} {product}";
                }
                else if (!string.IsNullOrEmpty(product))
                {
                    return product;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"CPE parsing hatası: {ex.Message}");
        }
        
        return "";
    }

    private static void DisplayCVEResults(System.Collections.Generic.List<CVEInfo> cveList, string source)
    {
        if (cveList.Count == 0)
        {
            Console.WriteLine($"  [{source}] CVE bulunamadı.");
        }
        else
        {
            Console.WriteLine($"  [{source}] {cveList.Count} CVE bulundu:");
            foreach (var cve in cveList)
            {
                Console.WriteLine($"    → CVE: {cve.Id}");
                Console.WriteLine($"       Açıklama: {cve.Description.Substring(0, Math.Min(80, cve.Description.Length))}...");
                Console.WriteLine($"       CVSS Puanı: {cve.CVSS}");
                Console.WriteLine($"       Exploit: {(cve.HasExploit ? "VAR" : "YOK")}");
                
                if (cve.CVSS >= 9.0)
                {
                    Console.WriteLine($"       KRITIK RISK SINIFI");
                }
                else if (cve.CVSS >= 7.0)
                {
                    Console.WriteLine($"       YUKSEK RISK SINIFI");
                }
                
                Console.WriteLine();
            }
        }
    }
}