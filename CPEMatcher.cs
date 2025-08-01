using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using FuzzySharp;
using System.Management;
using System;

public class CPEEntry
{
    public string CpeName { get; set; }
    public string Title { get; set; }
    public string Vendor { get; set; }
    public string Product { get; set; }
    
    // NIST CPE veritabanı için ek alanlar
    public string? Version { get; set; }
    public string? Update { get; set; }
    public string? Edition { get; set; }
    public string? Language { get; set; }
    public string? SwEdition { get; set; }
    public string? TargetSw { get; set; }
    public string? TargetHw { get; set; }
    public string? Other { get; set; }
}

// NIST CPE JSON formatı için alternatif sınıf
public class NistCPEEntry
{
    [JsonProperty("cpe23Uri")]
    public string? Cpe23Uri { get; set; }
    
    [JsonProperty("cpeName")]
    public string? CpeName { get; set; }
    
    [JsonProperty("lastModifiedDate")]
    public string? LastModifiedDate { get; set; }
    
    [JsonProperty("titles")]
    public List<CPETitle>? Titles { get; set; }
    
    [JsonProperty("refs")]
    public List<CPEReference>? References { get; set; }
    
    [JsonProperty("deprecated")]
    public bool Deprecated { get; set; }
}

public class CPETitle
{
    [JsonProperty("title")]
    public string? Title { get; set; }
    
    [JsonProperty("lang")]
    public string? Language { get; set; }
}

public class CPEReference
{
    [JsonProperty("ref")]
    public string? Reference { get; set; }
    
    [JsonProperty("type")]
    public string? Type { get; set; }
}

// NIST CPE veritabanının ana yapısı
public class NistCPEDatabase
{
    [JsonProperty("resultsPerPage")]
    public int ResultsPerPage { get; set; }
    
    [JsonProperty("startIndex")]
    public int StartIndex { get; set; }
    
    [JsonProperty("totalResults")]
    public int TotalResults { get; set; }
    
    [JsonProperty("result")]
    public NistCPEResult? Result { get; set; }
}

public class NistCPEResult
{
    [JsonProperty("dataType")]
    public string? DataType { get; set; }
    
    [JsonProperty("feedVersion")]
    public string? FeedVersion { get; set; }
    
    [JsonProperty("cpeCount")]
    public int CpeCount { get; set; }
    
    [JsonProperty("feedTimestamp")]
    public string? FeedTimestamp { get; set; }
    
    [JsonProperty("cpes")]
    public List<NistCPEEntry>? Cpes { get; set; }
}
public class CPEMatcher
{
    private List<CPEEntry> cpeList;

    public CPEMatcher(string dbPath)
    {
        try
        {
            if (!File.Exists(dbPath))
            {
                Console.WriteLine($"[HATA] CPE veritabanı dosyası bulunamadı: {dbPath}");
                cpeList = new List<CPEEntry>();
                return;
            }

            var json = File.ReadAllText(dbPath);
            Console.WriteLine($"[INFO] CPE veritabanı okunuyor. ({new FileInfo(dbPath).Length / 1024 / 1024} MB)");

            cpeList = new List<CPEEntry>();

            // NIST CPE formatını dene
            try
            {
                var nistDb = JsonConvert.DeserializeObject<NistCPEDatabase>(json);
                if (nistDb?.Result?.Cpes != null)
                {
                    Console.WriteLine("[INFO] NIST CPE formatı tespit edildi.");
                    
                    foreach (var nistEntry in nistDb.Result.Cpes)
                    {
                        if (nistEntry.Deprecated) continue; // Deprecated CPE'leri atla
                        
                        var cpeEntry = ConvertNistCPEToStandard(nistEntry);
                        if (cpeEntry != null)
                            cpeList.Add(cpeEntry);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[INFO] NIST formatı okunamadı, standart format deneniyor. ({ex.Message})");
                
                // Standart CPE array formatını dene
                try
                {
                    var standardList = JsonConvert.DeserializeObject<List<CPEEntry>>(json);
                    if (standardList != null)
                    {
                        cpeList = standardList;
                        Console.WriteLine("[INFO] Standart CPE array formatı kullanılıyor.");
                    }
                }
                catch
                {
                    // JSONL formatını dene (her satır ayrı JSON)
                    Console.WriteLine("[INFO] JSONL formatı deneniyor.");
                    var lines = json.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    
                    foreach (var line in lines)
                    {
                        try
                        {
                            var entry = JsonConvert.DeserializeObject<CPEEntry>(line.Trim());
                            if (entry != null)
                                cpeList.Add(entry);
                        }
                        catch
                        {
                            // Bu satırı atla
                        }
                    }
                }
            }

            // Veri kalitesi kontrolü
            cpeList = cpeList.Where(c => !string.IsNullOrWhiteSpace(c.CpeName) && 
                                        !string.IsNullOrWhiteSpace(c.Product))
                               .ToList();

            Console.WriteLine($"[INFO] {cpeList.Count} geçerli CPE girdisi yüklendi.");
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] CPE veritabanı yüklenemedi: {ex.Message}");
            cpeList = new List<CPEEntry>();
        }
    }

    private CPEEntry? ConvertNistCPEToStandard(NistCPEEntry nistEntry)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(nistEntry.Cpe23Uri))
                return null;

            // CPE 2.3 URI'sini parse et: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            var parts = nistEntry.Cpe23Uri.Split(':');
            if (parts.Length < 6) return null;

            var vendor = DecodeComponent(parts[3]);
            var product = DecodeComponent(parts[4]);
            var version = parts.Length > 5 ? DecodeComponent(parts[5]) : "";

            // Title'ı oluştur
            var title = nistEntry.Titles?.FirstOrDefault()?.Title ?? $"{vendor} {product}";

            return new CPEEntry
            {
                CpeName = nistEntry.Cpe23Uri,
                Title = title,
                Vendor = vendor,
                Product = product,
                Version = version
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UYARI] NIST CPE dönüştürme hatası: {ex.Message}");
            return null;
        }
    }

    private string DecodeComponent(string component)
    {
        if (string.IsNullOrWhiteSpace(component) || component == "*")
            return "";

        // CPE 2.3 özel karakterlerini decode et
        return component.Replace("\\!", "!")
                       .Replace("\\@", "@")
                       .Replace("\\#", "#")
                       .Replace("\\$", "$")
                       .Replace("\\%", "%")
                       .Replace("\\^", "^")
                       .Replace("\\&", "&")
                       .Replace("\\*", "*")
                       .Replace("\\(", "(")
                       .Replace("\\)", ")")
                       .Replace("\\-", "-")
                       .Replace("\\+", "+")
                       .Replace("\\=", "=")
                       .Replace("\\{", "{")
                       .Replace("\\}", "}")
                       .Replace("\\[", "[")
                       .Replace("\\]", "]")
                       .Replace("\\|", "|")
                       .Replace("\\\\", "\\")
                       .Replace("\\:", ":")
                       .Replace("\\;", ";")
                       .Replace("\\\"", "\"")
                       .Replace("\\'", "'")
                       .Replace("\\<", "<")
                       .Replace("\\>", ">")
                       .Replace("\\,", ",")
                       .Replace("\\.", ".")
                       .Replace("\\?", "?")
                       .Replace("\\/", "/")
                       .Replace("\\~", "~")
                       .Replace("\\`", "`")
                       .Replace("_", " ");
    }

    public string? FindBestCPE(string programName, bool enableDebug = false)
    {
        if (cpeList == null || cpeList.Count == 0 || string.IsNullOrWhiteSpace(programName))
            return null;

        // Program adını temizle
        string cleaned = CleanProgramName(programName);
        
        int maxScore = 0;
        string? bestCpe = null;
        string? bestTitle = null;
        var candidateMatches = new List<(CPEEntry entry, int score, string reason)>();

        foreach (var entry in cpeList)
        {
            // CPE verilerini temizle
            string cleanTitle = entry.Title?.Replace("_", " ").Trim() ?? "";
            string cleanVendor = entry.Vendor?.Replace("_", " ").Trim() ?? "";
            string cleanProduct = entry.Product?.Replace("_", " ").Trim() ?? "";

            // Farklı karşılaştırma stratejileri
            var scores = new Dictionary<string, int>
            {
                // Ana eşleşmeler
                ["title_exact"] = Fuzz.Ratio(cleaned.ToLower(), cleanTitle.ToLower()),
                ["product_exact"] = Fuzz.Ratio(cleaned.ToLower(), cleanProduct.ToLower()),
                ["vendor_exact"] = Fuzz.Ratio(cleaned.ToLower(), cleanVendor.ToLower()),
                
                // Orijinal isimle eşleşmeler
                ["title_orig"] = Fuzz.Ratio(programName.ToLower(), cleanTitle.ToLower()),
                ["product_orig"] = Fuzz.Ratio(programName.ToLower(), cleanProduct.ToLower()),
                ["vendor_orig"] = Fuzz.Ratio(programName.ToLower(), cleanVendor.ToLower()),
                
                // Kısmi eşleşmeler
                ["title_partial"] = Fuzz.PartialRatio(cleaned.ToLower(), cleanTitle.ToLower()),
                ["product_partial"] = Fuzz.PartialRatio(cleaned.ToLower(), cleanProduct.ToLower()),
                
                // Token tabanlı eşleşmeler
                ["title_token_sort"] = Fuzz.TokenSortRatio(cleaned.ToLower(), cleanTitle.ToLower()),
                ["product_token_sort"] = Fuzz.TokenSortRatio(cleaned.ToLower(), cleanProduct.ToLower()),
                ["title_token_set"] = Fuzz.TokenSetRatio(cleaned.ToLower(), cleanTitle.ToLower()),
                ["product_token_set"] = Fuzz.TokenSetRatio(cleaned.ToLower(), cleanProduct.ToLower()),
            };

            // En yüksek skoru ve nedenini bul
            var maxScoreEntry = scores.OrderByDescending(kvp => kvp.Value).First();
            int score = maxScoreEntry.Value;
            string reason = maxScoreEntry.Key;

            // Debugging için adayları topla
            if (score > 60 && enableDebug)
            {
                candidateMatches.Add((entry, score, reason));
            }

            // En iyi eşleşmeyi güncelle
            if (score > maxScore && score > 70) // Eşik değeri
            {
                maxScore = score;
                bestCpe = entry.CpeName;
                bestTitle = cleanTitle;
            }
        }

        // Debug çıktısı
        if (enableDebug && candidateMatches.Count > 0)
        {
            Console.WriteLine($"[DEBUG] '{programName}' için en iyi 5 aday:");
            foreach (var candidate in candidateMatches.OrderByDescending(c => c.score).Take(5))
            {
                Console.WriteLine($"  {candidate.score}% - {candidate.entry.Product} ({candidate.entry.Vendor}) [{candidate.reason}]");
            }
        }

        // Sonucu raporla
        if (bestCpe != null)
        {
            Console.WriteLine($"[CPE MATCH] '{programName}' -> '{bestTitle}' (score: {maxScore}%)");
            Console.WriteLine($"[CPE] {bestCpe}");
        }
        else
        {
            // Düşük skorlu ama potansiyel eşleşmeleri göster
            var bestCandidate = candidateMatches.OrderByDescending(c => c.score).FirstOrDefault();
            if (bestCandidate.entry != null)
            {
                Console.WriteLine($"[CPE] '{programName}' için kesin eşleşme yok. En yakın: {bestCandidate.entry.Product} ({bestCandidate.score}%)");
            }
            else
            {
                Console.WriteLine($"[CPE] '{programName}' için CPE bulunamadı");
            }
        }

        return bestCpe;
    }

    private string CleanProgramName(string programName)
    {
        // Yaygın gereksiz terimleri kaldır
        string cleaned = System.Text.RegularExpressions.Regex.Replace(
            programName,
            @"(\d{4}|\d+\.\d+(\.\d+)?|x64|x86|amd64|i386|win32|win64|minimum|runtime|redistributable|microsoft|update|hotfix|kb\d+|sp\d+|service pack|\(.*?\)|\[.*?\])",
            "",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
        );

        // Fazla boşlukları temizle
        cleaned = System.Text.RegularExpressions.Regex.Replace(cleaned, @"\s+", " ").Trim();
        
        return cleaned;
    }

    private string DecodeAndClean(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "";

        try
        {
            // URL decode işlemi
            string decoded = System.Web.HttpUtility.UrlDecode(input);
            
            // Özel karakterleri temizle
            decoded = decoded.Replace("_project", "")
                           .Replace("_", " ")
                           .Replace("%", "")
                           .Replace("(aka ", "")
                           .Replace(")", "")
                           .Replace("com.", "");

            // Fazla boşlukları temizle
            decoded = System.Text.RegularExpressions.Regex.Replace(decoded, @"\s+", " ").Trim();
            
            return decoded;
        }
        catch
        {
            // Decode edilemezse orijinali döndür
            return input.Replace("_", " ").Replace("%", "");
        }
    }
}

public class Example
{
    public void MatchCPE()
    {
        try
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Product");
            var cpeMatcher = new CPEMatcher("cpe_db.json");
            
            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"]?.ToString() ?? "Bilinmeyen";
                
                if (!string.IsNullOrWhiteSpace(name))
                {
                    Console.WriteLine($"\n--- Program: {name} ---");
                    string? bestCpe = cpeMatcher.FindBestCPE(name);
                    
                    if (bestCpe != null)
                    {
                        // CPE bulundu, şimdi bu CPE ile CVE araması yapabilirsin
                        Console.WriteLine($"CPE eşleşmesi bulundu: {bestCpe}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] CPE eşleme sırasında hata: {ex.Message}");
        }
    }
}