using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

public class CVEInfo
{
    public string Id { get; set; } = "N/A";
    public string Description { get; set; } = "Açıklama yok.";
    public double CVSS { get; set; } = 0.0;
    public string Severity { get; set; } = "NONE";
}

public class CVEParser
{
    public static List<CVEInfo> ParseCVEInfo(string json)
    {
        var results = new List<CVEInfo>();
        if (string.IsNullOrEmpty(json)) return results;

        try
        {
            JObject data = JObject.Parse(json);
            var vulnerabilities = data["vulnerabilities"];

            if (vulnerabilities == null || !vulnerabilities.Any())
            {
                return results;
            }

            foreach (var vuln in vulnerabilities)
            {
                var cve = vuln["cve"];
                if (cve == null) continue;

                // CVSS v3.1 verilerini önceliklendir
                var cvssMetric = cve["metrics"]?["cvssMetricV31"]?.FirstOrDefault() ?? cve["metrics"]?["cvssMetricV30"]?.FirstOrDefault();
                
                double score = 0.0;
                string severity = "NONE";

                if (cvssMetric != null)
                {
                    score = cvssMetric["cvssData"]?["baseScore"]?.Value<double>() ?? 0.0;
                    severity = cvssMetric["cvssData"]?["baseSeverity"]?.ToString() ?? "NONE";
                }
                else // Fallback to CVSS v2 if v3 is not available
                {
                    var cvssV2Metric = cve["metrics"]?["cvssMetricV2"]?.FirstOrDefault();
                    if(cvssV2Metric != null)
                    {
                        score = cvssV2Metric["cvssData"]?["baseScore"]?.Value<double>() ?? 0.0;
                        severity = cvssV2Metric["severity"]?.ToString().ToUpper() ?? "NONE";
                    }
                }

                results.Add(new CVEInfo
                {
                    Id = cve["id"]?.ToString() ?? "N/A",
                    Description = cve["descriptions"]?.FirstOrDefault(d => d["lang"]?.ToString() == "en")?["value"]?.ToString() ?? "Açıklama bulunamadı.",
                    CVSS = score,
                    Severity = severity
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] CVE JSON verisi ayrıştırılamadı: {ex.Message}");
        }

        return results.OrderByDescending(r => r.CVSS).ToList();
    }
}
