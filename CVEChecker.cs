using System.Net.Http;
using System;
using System.Threading.Tasks;

public class CVEChecker
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public CVEChecker(string apiKey)
    {
        _httpClient = new HttpClient();
        _apiKey = apiKey;
    }

    // Orijinal keyword araması
    public async Task<string?> GetCVEsAsync(string keyword)
    {
        string encodedKeyword = Uri.EscapeDataString(keyword);
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encodedKeyword}&resultsPerPage=5";

        return await MakeApiRequest(url, keyword);
    }

    // CPE ile CVE araması
    public async Task<string?> GetCVEsByCPEAsync(string cpeUri)
    {
        string encodedCpe = Uri.EscapeDataString(cpeUri);
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={encodedCpe}&resultsPerPage=5";

        return await MakeApiRequest(url, $"CPE: {cpeUri}");
    }

    // Vendor ve product ile CVE araması
    public async Task<string?> GetCVEsByVendorProductAsync(string vendor, string product)
    {
        string searchTerm = $"{vendor} {product}";
        string encodedSearch = Uri.EscapeDataString(searchTerm);
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encodedSearch}&resultsPerPage=5";

        return await MakeApiRequest(url, searchTerm);
    }

    // CVSS skoru ile filtreleme
    public async Task<string?> GetHighRiskCVEsAsync(string keyword, double minCvssScore = 7.0)
    {
        string encodedKeyword = Uri.EscapeDataString(keyword);
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encodedKeyword}&cvssV3Severity=HIGH&cvssV3Severity=CRITICAL&resultsPerPage=10";

        return await MakeApiRequest(url, $"{keyword} (High Risk)");
    }

    // Son N günden CVE'ler
    public async Task<string?> GetRecentCVEsAsync(string keyword, int lastDays = 30)
    {
        var endDate = DateTime.Now;
        var startDate = endDate.AddDays(-lastDays);
        
        string encodedKeyword = Uri.EscapeDataString(keyword);
        string startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ss.000");
        string endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ss.000");
        
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encodedKeyword}&lastModStartDate={startDateStr}&lastModEndDate={endDateStr}&resultsPerPage=5";

        return await MakeApiRequest(url, $"{keyword} (Son {lastDays} gün)");
    }

    private async Task<string?> MakeApiRequest(string url, string searchTerm)
    {
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("apiKey", _apiKey);

        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                string content = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[API] {searchTerm} için CVE verisi alındı");
                return content;
            }
            else
            {
                Console.WriteLine($"[HATA] API Hatası - Kod: {response.StatusCode} - {searchTerm}");
                
                if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    Console.WriteLine("[HATA] API anahtarı geçersiz veya rate limit aşıldı");
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    Console.WriteLine("[INFO] Bu arama terimi için CVE bulunamadı");
                }
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"[HATA] Ağ hatası: {ex.Message}");
        }
        catch (TaskCanceledException ex)
        {
            Console.WriteLine($"[HATA] İstek zaman aşımına uğradı: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] API isteği sırasında istisna oluştu: {ex.Message}");
        }

        return null;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}