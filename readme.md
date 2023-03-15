# adfsTorBlock

AD FS Risk Plugin that can block access to your AD FS servers from tor network.

## Overview

Since AD FS in Windows Server 2019 Microsoft provides possiblity to create custom module. By default Microsoft provides BannedIPs and Smart Lockout modules . The idea and concept of the plugin is described here - [Risk Assesment Framework](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model). My idea was to check and block access to the AD FS from the TOR network. In most situations the access to AD FS from TOR network is not something we would like to have.

## Disclaimer

Code is provided "AS IS" without any guarantee. Before using it, evaluate it on your lab / test environment.

## Installation

There is no installer for this ready yet.
For now you need to do steps described in here: [Risk Assesment Framework](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model). Because it's not automated yet, there are registry keys you need to add manually.
To register the plugin you need to invoke cmdlet `Register-AdfsThreatDetectionModule` with `-Name` and `-TypeName` parameters.
The Name is up to you while the TypeName is provided in the example below and must match the type returned by the plugin.

>`Register-AdfsThreatDetectionModule -Name "adfsTorBlock" -TypeName "adfsTorBlock.AdfsTorBlock, adfsTorBlock, Version=1.0.0.0, Culture=neutral, PublicKeyToken=f3ae4a32f7973774"`

## Usage

Plugin has three modes:

- Audit Mode
- Block Mode (enforcement mode)
- Risk Flag Mode

The settings are controlled through registry hive `HKEY_LOCAL_MACHINE\SOFTWARE\ADFSTorBlock`.
There are three `REG_DWORD` values you may setup:

- `Enabled`
- `AuditModeEnabled`
- `EvaluateRisk`

By deafult, if there is `ADFSTorBlock` key the plugin is going to operate in the Audit Mode.

### Updating configuration

Once you edit the registry the plugin has to reload the configuration. You may achive this by restarting the ad fs service or you may invoke the `Import-AdfsThreatDetectionModuleConfiguration` cmdlet which is a tricky one as by default it requires parameters `-Name` and `-ConfigurationFilePath`. As this plugin is using no configuration file, you may invoke this with path to existing, dummy file.

> `Import-AdfsThreatDetectionModuleConfiguration -Name adfsTorBlock -ConfigurationFilePath C:\dev\dummy.txt`

### Audit Mode

To enable the audit mode you need to make sure that `Enabled` value is set to 1 (or any different value than 0) And `AuditModeEnabled` value should also be 1.
This issues the events in the `AD FS/Admin` event log also with additional event that the request will be allowed due to audit mode. This mode allows you to first check the impact of the plugin without blocking any requests.

### Block Mode / Enforcement Mode

To enable this mode make sure that value `Enabled` is set to one while the others are set to 0.
This mode blocks each request comming to the AD FS that was found to be comming from IP address that belongs to TOR exit nodes. Also the event is noted in the `AD FS/Admin` event log.

### Risk Flag Mode

This was introduced to play with the capabilities of the module rather than the actuall need. The idea behind is simple - instead of blocking requests, let the relying party decide if they want to block it or not. In this case the request is allowed although the risk of the user is set to high (once the user was successfully authenticated). You may use the risk claim (`http://schemas.microsoft.com/ws/2017/04/identity/claims/riskscore`) to then block or enforce MFA for such user on the relying party trust using IssuanceAuthorizationRules, or AccessControlPolicies.
To set this mode you need to set `Enabled` to 1 and `EvaluateRisk` to 1. If you set `AuditModeEnabled` the flow will also work in audit mode it will produce the outcome but the risk claim will be set to `Not Evaluated`.

## Events and logging

The plugin uses standard logging method provided by the Framework which for every error / warning messages issues event `573` to `AD FS/Admin` event log. On [AD FS Error codes](https://adfshelp.microsoft.com/AdfsEventViewer/GetAdfsEventList) you may find the list of the error codes with it's structure.
Plugin also uses Debug messages that can be viewed by Sysinternal `DebugView` tool.

## Todo

- [ ]  Add Installer

## Further reading

[Risk Assesment Framework](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model)

## License

GNU General Public License v3.0
