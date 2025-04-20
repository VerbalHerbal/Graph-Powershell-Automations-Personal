#  Microsoft Graph PowerShell Automations

I created this repository as overtime I built a lot of handy Graph related automations for work purposes. I think that Graph API module, or API integrations in general, are really cool concepts and I wanted to share what I managed to build overtime with the hopes that someone else might find these useful.

> This repository also serves as my portfolio showcasing hands-on experience in modern endpoint management, security, and PowerShell scripting.

---

## About Me
**IT System Administrator / Engineer** with deep experience in:
- Enterprise automation (PowerShell + Graph)
- Intune/Endpoint config at scale
  - Specialization in mobile device management (iOS/Android/Windows devices)
- Secure app deployment + device control
- Azure/Entra/AAD scripting

Find me on [LinkedIn](https://www.linkedin.com/in/ceasar-h?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=ios_app)!

## Skills & Tools Demonstrated

![PowerShell](https://img.shields.io/badge/PowerShell-7.x-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Intune](https://img.shields.io/badge/Intune-Endpoint%20Manager-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Entra ID](https://img.shields.io/badge/Entra%20ID-Identity%20Management-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Defender for Endpoint](https://img.shields.io/badge/Defender%20for%20Endpoint-Security-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![App-only Auth](https://img.shields.io/badge/App--only%20Auth-Certificate%20Based-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Scripting-0078D4?style=for-the-badge&logo=githubactions&logoColor=white)
![Policy Enforcement](https://img.shields.io/badge/Policy%20Enforcement-Intune%20Policies-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)


---

## Repository Structure

| Folder        | Purpose                                                          |
|---------------|------------------------------------------------------------------|
| `Intune/`     | Scripts to manage USB access, app protection, device configs     |
| `EntraID/`    | User/group operations, stale device cleanup                      |
| `Reports/`    | Exporters for compliance, licenses, device and app info          |
| `docs/`       | Optional deep dives per script                                   |

---

## Getting Started

###  Requirements
- PowerShell 7.x
- Microsoft.Graph.Beta module / Microsoft.Graph module
- Azure App Registration with:
  - Certificate-based authentication
  - Delegated or application Graph API permissions

###  Used Permissions
```text
DeviceManagementManagedDevices.Read.All
Sites.Selected
BitlockerKey.Read.All
Device.ReadWrite.All
Directory.ReadWrite.All
Sites.ReadWrite.All
Directory.Read.All
User.Read.All
DeviceManagementServiceConfig.ReadWrite.All
DeviceLocalCredential.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.ReadWrite.All
GroupMember.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
DeviceManagementApps.ReadWrite.All
ThreatHunting.Read.All
```


# Security & Ethics
All scripts in this repo are sanitized of tenant-specific or corporate-sensitive data. Auth and configuration settings must be customized to your own environment before use.

---

### License
This project is licensed under the [MIT License](LICENSE). Free for personal, educational, or commercial use.

---


