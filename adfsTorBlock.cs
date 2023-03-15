using System.Threading.Tasks;
using Microsoft.IdentityServer.Public.ThreatDetectionFramework;
using System.Net;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Claims;

namespace adfsTorBlock
{
    public sealed class AdfsTorBlock : ThreatDetectionModule, IRequestReceivedThreatDetectionModule, IPostAuthenticationThreatDetectionModule
    {
        public override string VendorName => "Ignastech";
        public override string ModuleIdentifier => "adfsTorBlock";

        private Config _config;

        public override void OnAuthenticationPipelineLoad(ThreatDetectionLogger adfslogger, ThreatDetectionModuleConfiguration configData)
        {
            Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Initation of the plugin");
            try
            {
                _config = new Config();
                _config.InitConfig();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Exception loading config: {ex}");
                throw;
            } 
            Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Loaded Config: {_config}");
        }
        public override void OnAuthenticationPipelineUnload(ThreatDetectionLogger adfslogger)
        {
        }

        public override void OnConfigurationUpdate(ThreatDetectionLogger adfslogger, ThreatDetectionModuleConfiguration configData)
        {
            Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Updating plugin config");
            try
            {
                _config = new Config();
                _config.InitConfig();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Exception loading config: {ex}");
                throw;
            }
            Debug.WriteLine($"adfsTorBlock:OnAuthenticationPipelineLoad:Loaded Config: {_config}");
        }

        public Task<ThrottleStatus> EvaluateRequest(ThreatDetectionLogger adfslogger, RequestContext requestContext)
        {
            Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Enter");
            Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Request for '{requestContext.LocalEndPointAbsolutePath}'");
            Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Checking if plugin is enabled and Risk Evaluation is disabled");
            if (_config.Enabled == true && _config.EvaluateRisk == false)
            {
                Debug.WriteLine("adfsTorBlock:EvaluateRequest:Plugin enabled");
                Debug.WriteLine("adfsTorBlock:EvaluateRequest:Checking if audit mode is enabled is enabled");
                bool Block;
                if (_config.AuditModeEnabled == true)
                {
                    Debug.WriteLine("adfsTorBlock:EvaluateRequest:Audit mode is enabled");
                    adfslogger.WriteAdminLogErrorMessage($"AUDIT MODE: Tor Block Audit Mode is enabled. Requests from Tor exit nodes will be allowed");
                    Block = false;
                }
                else
                {
                    Debug.WriteLine("adfsTorBlock:EvaluateRequest:Audit mode is disabled");
                    Block = true;
                }
                foreach (IPAddress ipAddress in requestContext.ClientIpAddresses)
                {
                    if (TorModule.IsTorExitNode(ipAddress))
                    {
                        Debug.WriteLine($"adfsTorBlock:EvaluateRequest:'{ipAddress}' is from Tor network");
                        string detailsMessage = $"\n\nRequest from '{ipAddress}' has been found to be from Tor network. Request DENIED.\n\n" +
                            $"Incoming Request details:\n" +
                            $"Local endpoint: {requestContext.LocalEndPointAbsolutePath}\n" +
                            $"HTTP Method: {requestContext.HttpMethod}\n" +
                            $"Correlation ID: {requestContext.CorrelationId}\n" +
                            $"Client Location: {requestContext.ClientLocation}\n" +
                            $"User Agent: {requestContext.UserAgentString}\n" +
                            $"Incoming Request Type: {requestContext.IncomingRequestType}\n" +
                            $"Proxy Server: {requestContext.ProxyServer}\n";

                        adfslogger.WriteAdminLogErrorMessage($"{detailsMessage}");
                        Debug.WriteLine($"adfsTorBlock:EvaluateRequest:'{detailsMessage}");
                        if (Block == true)
                        {
                            Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Blocking Request");
                            return Task.FromResult(ThrottleStatus.Block);
                        }
                        else
                        {
                            Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Allowing Request");
                            return Task.FromResult(ThrottleStatus.Allow);
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"adfsTorBlock:EvaluateRequest:'{ipAddress}' is not from Tor network");
                    }
                }
            }
            else
            {
                if(_config.EvaluateRisk == true)
                {
                    Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Plugin is in Risk evaluation Mode.");
                    return Task.FromResult(ThrottleStatus.Allow);
                }
                else
                {
                    Debug.WriteLine($"adfsTorBlock:EvaluateRequest:Plugin is not enabled");
                    return Task.FromResult(ThrottleStatus.NotEvaluated);
                }
            }
            return Task.FromResult(ThrottleStatus.NotEvaluated);
        }

        Task<RiskScore> IPostAuthenticationThreatDetectionModule.EvaluatePostAuthentication(ThreatDetectionLogger adfslogger, RequestContext requestContext, SecurityContext securityContext, ProtocolContext protocolContext, AuthenticationResult authenticationResult, IList<Claim> additionalClams)
        {
            Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:Enter");
            Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:Request for '{requestContext.LocalEndPointAbsolutePath}'");
            Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:Checking if plugin and risk evaluation is enabled");
            if (_config.Enabled == true && _config.EvaluateRisk == true)
            {
                Debug.WriteLine("adfsTorBlock:EvaluatePostAuthentication:Plugin and Risk Evaluation enabled");
                Debug.WriteLine("adfsTorBlock:EvaluatePostAuthentication:Checking if audit mode is enabled is enabled");
                bool EvaluateRisk;
                if (_config.AuditModeEnabled == true)
                {
                    Debug.WriteLine("adfsTorBlock:EvaluatePostAuthentication:Audit mode is enabled");
                    adfslogger.WriteAdminLogErrorMessage($"\n\nAUDIT MODE: Tor Block Audit Mode is enabled. RiskScore of reuqests from Tor exit nodes won't be evaluated");
                    EvaluateRisk = false;
                }
                else
                {
                    Debug.WriteLine("adfsTorBlock:EvaluatePostAuthentication:Audit mode is disabled");
                    EvaluateRisk = true;
                }
                foreach (IPAddress ipAddress in requestContext.ClientIpAddresses)
                {
                    if (TorModule.IsTorExitNode(ipAddress))
                    {
                        Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:'{ipAddress}' is from Tor network");
                        adfslogger.WriteAuditMessage($"Icoming request IP address '{ipAddress}' discovered to be from Tor Network");
                        string detailsMessage = $"\n\nRequest from '{ipAddress}' has been found to be from Tor network. Risk will be set to High.\n\n" +
                            $"Incoming Request details:\n" +
                            $"Local endpoint: {requestContext.LocalEndPointAbsolutePath}\n" +
                            $"HTTP Method: {requestContext.HttpMethod}\n" +
                            $"Correlation ID: {requestContext.CorrelationId}\n" +
                            $"Client Location: {requestContext.ClientLocation}\n" +
                            $"User Agent: {requestContext.UserAgentString}\n" +
                            $"Incoming Request Type: {requestContext.IncomingRequestType}\n" +
                            $"User Identifier: {securityContext.UserIdentifier}\n" +
                            $"Device Authentication Result: {securityContext.DeviceAuthenticationResult}\n" +
                            $"Authority: {securityContext.Authority}\n" +
                            $"AuthProtocol: {protocolContext.AuthProtocol}\n" +
                            $"Resource: {protocolContext.Resource}\n" +
                            $"ClientId: {protocolContext.ClientId}\n" +
                            $"authenticationResult: {authenticationResult}\n";
                        Claim claim1 = new Claim("https://sts.ignastech.cloud/adfs/adfsTorBlock", "HighRisk", ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer);
                        additionalClams.Add(claim1);
                        adfslogger.WriteAdminLogErrorMessage($"{detailsMessage}");
                        Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:'{detailsMessage}");
                        if (EvaluateRisk == true)
                        {
                            Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:Evaluating risk to High. Reuqest from TOR network");
                            return Task.FromResult(RiskScore.High);
                        }
                        else
                        {
                            Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:Risk not evaluated due to audit mode");
                            return Task.FromResult(RiskScore.NotEvaluated);
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"adfsTorBlock:EvaluatePostAuthentication:'{ipAddress}' is not from Tor network");
                    }
                }
            }
            else
            {
                return Task.FromResult(RiskScore.NotEvaluated);
            }
            return Task.FromResult(RiskScore.NotEvaluated);
        }

    }
}
