using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

public class CVEInfo
{
    public string Id { get; set; }
    public string Description { get; set; }
    public double CVSS { get; set; }
    public bool HasExploit { get; set; }
}

public class CVEParser
{
    public static List<CVEInfo> ParseCVEInfo(string json)
    {
        var results = new List<CVEInfo>();

        JObject data = JObject.Parse(json);
        var vulnerabilities = data["vulnerabilities"];

        if (vulnerabilities != null)
        {
            foreach (var vuln in vulnerabilities)
            {
                try
                {
                    var cve = vuln["cve"];
                    string id = cve["id"]?.ToString() ?? "N/A";
                    string description = cve["descriptions"]?[0]?["value"]?.ToString() ?? "N/A";
                    string scoreStr = cve["metrics"]?["cvssMetricV31"]?[0]?["cvssData"]?["baseScore"]?.ToString() ??
                                      cve["metrics"]?["cvssMetricV2"]?[0]?["cvssData"]?["baseScore"]?.ToString() ??
                                      "0.0";

                    double score = double.TryParse(scoreStr, out var s) ? s : 0.0;

                    // CVE'lerde "exploit" bilgisi net şekilde dönmeyebilir, örnek olarak yüksek puanlı olanları exploit var sayıyoruz
                    bool hasExploit = score >= 7.0;

                    results.Add(new CVEInfo
                    {
                        Id = id,
                        Description = description,
                        CVSS = score,
                        HasExploit = hasExploit
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Hata (CVE parse): {ex.Message}");
                }
            }
        }

        return results;
    }
}
