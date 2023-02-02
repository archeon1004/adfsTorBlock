using Microsoft.Win32;
using System;
using System.Diagnostics;

namespace adfsTorBlock
{
    internal class Config
    {
        private const string regPath = "SOFTWARE\\ADFSTorBlock";
        internal bool Enabled { get; set; }
        internal bool AuditModeEnabled { get; set; } 
        internal bool EvaluateRisk { get; set; }

        public Config()
        {
            try
            {
                RegistryKey rk = Registry.LocalMachine.OpenSubKey(regPath);
                if (rk == null)
                {
                    throw new InvalidOperationException("RegistryKeyException");
                }
                object oEnabled = rk.GetValue("Enabled");
                if (oEnabled != null)
                {
                    Enabled = oEnabled.ToString() == "0" ? false : true;
                }
                
                object oAuditModeEnabled = rk.GetValue("AuditModeEnabled");
                if (oAuditModeEnabled != null)
                {
                    AuditModeEnabled = oAuditModeEnabled.ToString() == "0" ? false : true;
                }
                object oEvaluateRisk = rk.GetValue("EvaluateRisk");
                if (oEvaluateRisk != null)
                {
                    EvaluateRisk = oEvaluateRisk.ToString() == "0" ? false : true;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"adfsTorBlock:{this.GetType()}:Config constructor:Exception caught: {ex}");
                Debug.WriteLine($"adfsTorBlock:{this.GetType()}:Config constructor:Setting default values");
                Enabled = true;
                AuditModeEnabled = true;
                EvaluateRisk = false;
            }
        }
        public override string ToString() => $"Enabled: {Enabled};AuditModeEnabled: {AuditModeEnabled};EvaluateRisk: {EvaluateRisk}";
        public void InitConfig()
        {
            Debug.WriteLine($"adfsTorBlock:{this.GetType()}:InitConfig:Enter");
            Debug.WriteLine($"adfsTorBlock:{this.GetType()}:Reading Plugin Registry Configuration Configuration");
            try
            {
                Debug.WriteLine($"adfsTorBlock:{this.GetType()}:Loading Tor Exit Nodes");
                TorModule.LoadTorExitNodes();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"adfsTorBlock:{this.GetType()}: LoadTorExitNodes - Exception. {ex}");
            }
            Debug.WriteLine($"adfsTorBlock:{this.GetType()}:InitConfig:Exit");
        }
    }
}
