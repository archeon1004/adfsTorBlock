using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Diagnostics;

namespace adfsTorBlock
{
    internal class TorModule
    {
        private static HashSet<IPAddress> torExitNodes = new HashSet<IPAddress>();
        internal static void LoadTorExitNodes()
        {
            string url = "https://check.torproject.org/exit-addresses";
            using (WebClient client = new WebClient())
            {
                try
                {
                    string text = client.DownloadString(url);
                    using (StringReader reader = new StringReader(text))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (line.StartsWith("ExitAddress"))
                            {
                                string[] parts = line.Split(' ');
                                if (parts.Length >= 2)
                                {
                                    string address = parts[1];
                                    try
                                    {
                                        Debug.WriteLine($"adfsTorBlock:torModule:LoadTorExitNodes: adding '{address}' to Tor Exit Nodes");
                                        torExitNodes.Add(IPAddress.Parse(address));
                                    }
                                    catch (FormatException ex)
                                    {
                                        Debug.WriteLine($"adfsTorBlock:torModule:LoadTorExitNodes: Exception parsing IP Address: {ex}");
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"adfsTorBlock:torModule:LoadTorExitNodes: Exception loading Tor Nodes IP Address: {ex}");
                    throw;
                }
            }
        }
        internal static bool IsTorExitNode(IPAddress address)
        {
            return torExitNodes.Contains(address);
        }
    }
}
