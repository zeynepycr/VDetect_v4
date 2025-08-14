using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using FuzzySharp;
using System.Management;
using System;
using System.Text.RegularExpressions;

public class CPEEntry
{
    public string CpeName { get; set; }
    public string Title { get; set; }
    public string Vendor { get; set; }
    public string Product { get; set; }

}

// NIST formatı için sınıflar
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
    private List<CPEEntry> _cpeList;
    public bool IsInitialized { get; private set; } = false;

    // "7-Zip" -> "Igor Pavlov" gibi algoritmaların yakalayamayacağı durumlar için hardcoded eşleştirme
    private readonly Dictionary<string, string> _hardcodedMatches = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        { "7-zip", "igor_pavlov 7-zip" },
        { "7zip", "igor_pavlov 7-zip" },
        { "notepad++", "notepad-plus-plus" },
        { "notepad plus plus", "notepad-plus-plus" },
        { "visual studio code", "microsoft visual_studio_code" },
        { "vscode", "microsoft visual_studio_code" },
        { "vs code", "microsoft visual_studio_code" },
        
        // Microsoft ürünleri
        { "microsoft visual c++", "microsoft visual_c" },
        { "microsoft visual c", "microsoft visual_c" },
        { "microsoft .net", "microsoft .net" },
        { "microsoft asp.net", "microsoft asp.net" },
        { "microsoft windows", "microsoft windows" },
        { "office", "microsoft office" },
        { "microsoft office", "microsoft office" },
        
        // Tarayıcılar
        { "google chrome", "google chrome" },
        { "chrome", "google chrome" },
        { "mozilla firefox", "mozilla firefox" },
        { "firefox", "mozilla firefox" },
        { "microsoft edge", "microsoft edge" },
        { "edge", "microsoft edge" },
        
        // Diğer popüler uygulamalar
        { "adobe reader", "adobe acrobat_reader" },
        { "adobe acrobat", "adobe acrobat" },
        { "java", "oracle java" },
        { "oracle java", "oracle java" },
        { "node.js", "nodejs node.js" },
        { "nodejs", "nodejs node.js" },
        { "python", "python python" },
        { "git", "git git" },
        { "putty", "simon_tatham putty" },
        { "wireshark", "wireshark wireshark" },
        { "virtualbox", "oracle virtualbox" },
        { "vmware", "vmware vmware_workstation" },
        { "teamviewer", "teamviewer teamviewer" },
        { "anydesk", "anydesk anydesk" },
        { "discord", "discord discord" },
        { "steam", "valve steam" },
        { "origin", "electronic_arts origin" },
        { "ea app", "electronic_arts origin" },
        { "battle.net", "blizzard_entertainment battle.net" },
        { "epic games launcher", "epic_games epic_games_launcher" },
        { "epic games", "epic_games epic_games_launcher" }
    };
    public CPEMatcher(string dbPath)
    {
        try
        {
            if (!File.Exists(dbPath))
            {
                Console.WriteLine($"[HATA] CPE veritabanı dosyası bulunamadı: {dbPath}");
                _cpeList = new List<CPEEntry>();
                return;
            }

            var json = File.ReadAllText(dbPath);
            Console.WriteLine($"[INFO] CPE veritabanı okunuyor. (~{new FileInfo(dbPath).Length / 1024 / 1024} MB)");

            // Öncelik: Standart array formatı
            if (TryLoadStandardArray(json, out var listFromStandard))
            {
                _cpeList = listFromStandard!;
                Console.WriteLine($"[INFO] Standart CPE formatı yüklendi. Toplam Kayıt: {_cpeList.Count}");
            }
            else if (TryLoadNist(json, out var listFromNist))
            {
                _cpeList = listFromNist!;
                Console.WriteLine($"[INFO] NIST CPE formatı yüklendi. Toplam Kayıt: {_cpeList.Count}");
            }
            else if (TryLoadJsonl(json, out var listFromJsonl))
            {
                _cpeList = listFromJsonl!;
                Console.WriteLine($"[INFO] JSONL CPE formatı yüklendi. Toplam Kayıt: {_cpeList.Count}");
            }
            else
            {
                Console.WriteLine("[HATA] CPE veritabanı formatı tanınamadı veya boş.");
                _cpeList = new List<CPEEntry>();
                return;
            }

            _cpeList = _cpeList
                .Where(c => !string.IsNullOrWhiteSpace(c.CpeName) && !string.IsNullOrWhiteSpace(c.Product))
                .ToList();

            Console.WriteLine($"[INFO] {_cpeList.Count} geçerli CPE girdisi kullanıma hazır.");
            IsInitialized = _cpeList.Any();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] CPE veritabanı yüklenemedi: {ex.Message}");
            _cpeList = new List<CPEEntry>();
        }
    }

    private bool TryLoadStandardArray(string json, out List<CPEEntry>? list)
    {
        list = null;
        try
        {
            var arr = JsonConvert.DeserializeObject<List<CPEEntry>>(json);
            if (arr != null && arr.Count > 0)
            {
                list = arr;
                return true;
            }
        }
        catch { }
        return false;
    }

    private bool TryLoadSingleObject(string json, out List<CPEEntry>? list)
    {
        list = null;
        try
        {
            var obj = JsonConvert.DeserializeObject<CPEEntry>(json);
            if (obj != null && !string.IsNullOrWhiteSpace(obj.CpeName))
            {
                list = new List<CPEEntry> { obj };
                return true;
            }
        }
        catch { }
        return false;
    }

    private bool TryLoadJsonl(string json, out List<CPEEntry>? list)
    {
        list = new List<CPEEntry>();
        try
        {
            var lines = json.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                try
                {
                    var entry = JsonConvert.DeserializeObject<CPEEntry>(line.Trim());
                    if (entry != null && !string.IsNullOrWhiteSpace(entry.CpeName))
                        list.Add(entry);
                }
                catch { }
            }
            if (list.Count > 0) return true;
        }
        catch { }
        list = null;
        return false;
    }

    private bool TryLoadNist(string json, out List<CPEEntry>? list)
    {
        list = new List<CPEEntry>();
        try
        {
            var nistDb = JsonConvert.DeserializeObject<NistCPEDatabase>(json);
            var cpes = nistDb?.Result?.Cpes;
            if (cpes == null || cpes.Count == 0)
            {
                list = null;
                return false;
            }

            foreach (var nistEntry in cpes)
            {
                if (nistEntry.Deprecated) continue;
                var converted = ConvertNistCPEToStandard(nistEntry);
                if (converted != null) list.Add(converted);
            }
            return list.Count > 0;
        }
        catch
        {
            list = null;
            return false;
        }
    }

    private CPEEntry? ConvertNistCPEToStandard(NistCPEEntry nistEntry)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(nistEntry.Cpe23Uri))
                return null;

            var parts = nistEntry.Cpe23Uri.Split(':');
            if (parts.Length < 6) return null;

            var vendor = DecodeComponent(parts[3]);
            var product = DecodeComponent(parts[4]);
            var version = parts.Length > 5 ? DecodeComponent(parts[5]) : "";

            var title = nistEntry.Titles?.FirstOrDefault()?.Title ?? $"{vendor} {product}".Trim();

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
        if (string.IsNullOrWhiteSpace(component) || component == "*") return "";
        return component.Replace("\\:", ":")
                        .Replace("\\*", "*")
                        .Replace("_", " ");
    }

    public string? FindBestCPE(string programName, string? version, bool enableDebug = false, bool useHardcodedFallback = false)
    {
        if (_cpeList == null || !_cpeList.Any() || string.IsNullOrWhiteSpace(programName))
            return null;

        string cleanedProgramName = CleanProgramNameForSearch(programName).ToLower();
        string programVersion = ExtractVersion(version ?? programName) ?? "";

        double maxScore = 0;
        CPEEntry? bestEntry = null;

        // Daha akıllı ön filtreleme - tam isim eşleşmesi öncelikli
        var potentialMatches = new List<CPEEntry>();
        
        // 1. Tam isim eşleşmesi ara
        var exactMatches = _cpeList.AsParallel()
            .Where(c => c.Product.Equals(cleanedProgramName, StringComparison.OrdinalIgnoreCase) || 
                       c.Title.Equals(cleanedProgramName, StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        if (exactMatches.Any())
        {
            potentialMatches.AddRange(exactMatches);
        }
        else
        {
            // 2. Anahtar kelime eşleşmesi ara (en az 2 ortak anahtar kelime zorunlu)
            var candidateKeywords = cleanedProgramName.Split(' ').Where(k => k.Length > 2).Distinct().ToList();
            var keywordMatches = _cpeList.AsParallel()
                .Where(c =>
                {
                    string target = ($"{c.Product} {c.Title}").ToLower();
                    int overlapCount = candidateKeywords.Count(kw => target.Contains(kw));
                    return overlapCount >= Math.Min(2, candidateKeywords.Count);
                })
                .ToList();
            potentialMatches.AddRange(keywordMatches);
        }

        if (enableDebug) Console.WriteLine($"[DEBUG] Aday CPE sayısı: {potentialMatches.Count}");


        foreach (var entry in potentialMatches)
        {
            double currentScore = 0;

            string cpeProduct = (entry.Product ?? "").ToLower();
            string cpeTitle = (entry.Title ?? "").ToLower();
            string cpeVendor = (entry.Vendor ?? "").ToLower();

            // 1. Temel Puan: Fuzzy string matching (birden fazla algoritma)
            int titleScore = Fuzz.TokenSetRatio(cleanedProgramName, cpeTitle);
            int productScore = Fuzz.TokenSetRatio(cleanedProgramName, cpeProduct);
            int partialRatio = Fuzz.PartialRatio(cleanedProgramName, cpeTitle);
            int tokenSortRatio = Fuzz.TokenSortRatio(cleanedProgramName, cpeTitle);
            
            // En yüksek fuzzy skorunu al
            currentScore = Math.Max(Math.Max(titleScore, productScore), Math.Max(partialRatio, tokenSortRatio));

            // 2. Bonus: Vendor (sağlayıcı) eşleşmesi
            if (!string.IsNullOrEmpty(cpeVendor) && cleanedProgramName.Contains(cpeVendor))
            {
                currentScore += 10;
            }

            // 3. Bonus: Product (ürün) eşleşmesi
            if (cleanedProgramName.Contains(cpeProduct))
            {
                currentScore += 5;
            }

            // 4. En Önemli Bonus: Versiyon eşleşmesi
            if (!string.IsNullOrEmpty(programVersion) && !string.IsNullOrEmpty(entry.Version) && entry.Version != "*" && entry.Version != "-")
            {
                string cpeVersion = ExtractVersion(entry.Version) ?? "";
                if (programVersion == cpeVersion)
                {
                    currentScore += 30; // Tam versiyon eşleşmesi çok güçlü bir sinyaldir
                }
            }

            if (currentScore > maxScore)
            {
                maxScore = currentScore;
                bestEntry = entry;
            }
        }

        const int MIN_CONFIDENCE_SCORE = 80; // Biraz daha düşük eşik değeri
        if (maxScore >= MIN_CONFIDENCE_SCORE && bestEntry != null)
        {
            if (enableDebug)
            {
                Console.WriteLine($"[CPE MATCH] '{programName}' -> '{bestEntry.Title}' (Skor: {maxScore:F2})");
            }
            return bestEntry.CpeName;
        }

        if (enableDebug)
        {
            Console.WriteLine($"[CPE] '{programName}' için güvenilir CPE bulunamadı. En iyi skor: {maxScore:F2} ({bestEntry?.Title})");
        }

        if (useHardcodedFallback)
        {
            string lowerOriginal = programName.ToLower();
            string? mapped = null;
            foreach (var kv in _hardcodedMatches)
            {
                string key = kv.Key.ToLower();
                if (System.Text.RegularExpressions.Regex.IsMatch(lowerOriginal, $@"(^|\b){System.Text.RegularExpressions.Regex.Escape(key)}(\b|$)"))
                {
                    mapped = kv.Value;
                    break;
                }
            }

            if (!string.IsNullOrWhiteSpace(mapped))
            {
                if (enableDebug) Console.WriteLine($"[DEBUG] Hardcoded fallback denenecek: {programName} -> {mapped}");

                string fallbackClean = CleanProgramNameForSearch(mapped).ToLower();
                var fallbackKeywords = fallbackClean.Split(' ').Where(k => k.Length > 2).Distinct().ToList();
                var fallbackCandidates = _cpeList.AsParallel()
                    .Where(c =>
                    {
                        string target = ($"{c.Product} {c.Title}").ToLower();
                        int overlapCount = fallbackKeywords.Count(kw => target.Contains(kw));
                        return overlapCount >= Math.Min(2, fallbackKeywords.Count) ||
                               c.Product.Equals(fallbackClean, StringComparison.OrdinalIgnoreCase) ||
                               c.Title.Equals(fallbackClean, StringComparison.OrdinalIgnoreCase);
                    })
                    .ToList();

                double fbMax = 0;
                CPEEntry? fbBest = null;
                foreach (var entry in fallbackCandidates)
                {
                    double score = 0;
                    string cpeProduct = (entry.Product ?? "").ToLower();
                    string cpeTitle = (entry.Title ?? "").ToLower();
                    int s1 = Fuzz.TokenSetRatio(fallbackClean, cpeTitle);
                    int s2 = Fuzz.TokenSetRatio(fallbackClean, cpeProduct);
                    int s3 = Fuzz.PartialRatio(fallbackClean, cpeTitle);
                    int s4 = Fuzz.TokenSortRatio(fallbackClean, cpeTitle);
                    score = Math.Max(Math.Max(s1, s2), Math.Max(s3, s4));

                    if (!string.IsNullOrEmpty(programVersion) && !string.IsNullOrEmpty(entry.Version) && entry.Version != "*" && entry.Version != "-")
                    {
                        string cpeVersion = ExtractVersion(entry.Version) ?? "";
                        if (programVersion == cpeVersion)
                        {
                            score += 30;
                        }
                    }

                    if (score > fbMax)
                    {
                        fbMax = score;
                        fbBest = entry;
                    }
                }

                if (fbMax >= 80 && fbBest != null)
                {
                    if (enableDebug)
                    {
                        Console.WriteLine($"[CPE MATCH - Fallback] '{programName}' -> '{fbBest.Title}' (Skor: {fbMax:F2})");
                    }
                    return fbBest.CpeName;
                }
            }
        }

        return null;
    }

    public static string CleanProgramNameForSearch(string programName)
    {
        // Daha akıllı temizleme - sadece gereksiz suffix'leri kaldır
        string cleaned = programName;
        
        // Versiyon numaralarını kaldır (sadece sonundaki)
        cleaned = Regex.Replace(cleaned, @"\s*-\s*\d+(\.\d+)*$", "", RegexOptions.IgnoreCase);
        
        // Gereksiz suffix'leri kaldır
        cleaned = Regex.Replace(cleaned, @"\s*(x64|x86|amd64|win32|win64|64-bit|32-bit|minimum|runtime|redistributable|update|hotfix|kb\d+|sp\d+)\s*$", "", RegexOptions.IgnoreCase);
        
        // Parantez içindeki gereksiz bilgileri kaldır
        cleaned = Regex.Replace(cleaned, @"\s*\([^)]*(?:x64|x86|amd64|win32|win64|64-bit|32-bit|minimum|runtime|redistributable|update|hotfix|kb\d+|sp\d+)[^)]*\)", "", RegexOptions.IgnoreCase);
        
        // Fazla boşlukları temizle
        cleaned = Regex.Replace(cleaned, @"\s+", " ").Trim();
        
        return cleaned;
    }
    private string? ExtractVersion(string text)
    {
        // Genel versiyon numarası formatlarını yakalar (örn: 14.40.33810, 8.1.2, v1.2)
        var match = Regex.Match(text, @"(\d+(\.\d+){1,3})");
        if (match.Success)
        {
            return match.Value;
        }
        return null;
    }
}

