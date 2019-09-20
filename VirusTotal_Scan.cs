using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;

namespace VirusTotalNET.Client
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            await RunScan();
            Console.WriteLine("Press a key to continue");
            Console.ReadLine();
        }
        public static async Task RunScan()
        {
            VirusTotal virusTotal = new VirusTotal("YOUR VT API KEY HERE");
            virusTotal.UseTLS = true;

        
            using (StreamReader scanHosts = new StreamReader(@"address.txt"))
            {
                string line;

                while ((line = scanHosts.ReadLine()) != null)
                {
                    try
                    {
                        Console.WriteLine("Hostname: " + line);
                        UrlReport urlreport = await virusTotal.GetUrlReportAsync(line);
                        PrintScan(urlreport);
                    }
                    catch (VirusTotalNET.Exceptions.RateLimitException)
                    {
                        Thread.Sleep(60000);
                        continue;  
                    }
                    catch (VirusTotalNET.Exceptions.InvalidResourceException)
                    {
                        Console.WriteLine("-- Blank Entry --");
                        Console.WriteLine();
                        continue;
                    }
                }
            }  
        }
        private static void PrintScan(UrlReport urlReport)
        {
            Console.WriteLine("Scan Date: " + urlReport.ScanDate);
            Console.WriteLine("Scan Link: " + urlReport.Permalink);
            Console.WriteLine("Host Detections: " + urlReport.Positives + "/" + urlReport.Total);
            
            if (urlReport.ResponseCode == UrlReportResponseCode.Present)
            {
                foreach (KeyValuePair<string, UrlScanEngine> scan in urlReport.Scans)
                {
                    if (scan.Value.Detected)
                    {
                        Console.BackgroundColor = ConsoleColor.White;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("WARNING: Posible Malicious Host Detected");
                        Console.ResetColor();
                    }
                }
            }
            Console.WriteLine();   
        }
    }
}

