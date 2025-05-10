## 🖥️ 1. Endpoint Preparation (Windows 10 VM)

To simulate endpoint activity and generate telemetry for Wazuh, I provisioned a Windows 10 virtual machine. This endpoint is where Mimikatz is executed and Sysmon is installed to produce relevant security events. The VM runs on VirtualBox with Host-only and NAT adapters for isolated testing and connectivity with the SIEM components.

### ⚙️ 1.1 VirtualBox Installation

VirtualBox is used as the hypervisor to run the Windows VM locally.

- [VirtualBox Download](https://www.virtualbox.org/wiki/Downloads)
- VirtualBox Version: `7.x`
- Extension Pack: Installed (for additional features like clipboard sharing and USB passthrough)

> ⚠️ Ensure virtualization is enabled in BIOS/UEFI.

### 🧱 1.2 VM Creation and Configuration

The Windows 10 VM was provisioned with the following configuration:

| Setting        | Value             |
|----------------|------------------|
| VM Name        | `WIN10-ENDPOINT` |
| OS Type        | Windows 10 (64-bit) |
| Memory         | 8 GB              |
| vCPUs          | 2                 |
| Disk Size      | 50 GB (Dynamic)   |
| Network        | NAT + Host-Only   |

#### Steps:

1. Open VirtualBox and click `New`.
2. Set the name to `WIN10-ENDPOINT`, OS to `Windows 10 (64-bit)`.
3. Allocate 8192 MB RAM and 2 vCPUs.
4. Create a VDI disk (dynamically allocated, 50GB).
5. Mount the Windows 10 ISO in **Settings > Storage > Optical Drive**.
6. Attach both NAT and Host-only adapters in **Settings > Network**.
7. Start the VM and complete Windows installation.

<details>
<summary>📷 Screenshot - Windows 10 VM Running</summary>

![VM Running](https://github.com/user-attachments/assets/506d1411-27de-4d89-bfc7-c055f131641e)

</details>

### 🔧 1.3 Sysmon Installation (for Event Logging)

To capture low-level system events for detection use-cases, I installed Sysmon with a modular config.

#### Steps:

1. Download Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon  
2. Extract contents to: `C:\Tools\Sysmon\`

    ```
    Sysmon64.exe
    Sysmon.exe
    EULA.txt
    ```

3. Download a modular config from Olaf Hartong’s repo:  
   https://github.com/olafhartong/sysmon-modular

   Save the `sysmonconfig.xml` to `C:\Tools\Sysmon\`.

4. Run Sysmon from PowerShell (Admin):

    ```powershell
    cd "C:\Tools\Sysmon"
    .\Sysmon64.exe -i sysmonconfig.xml
    ```

5. Confirm service is running:

    ```powershell
    Get-Service Sysmon64
    ```

6. Logs will now appear in:

    ```
    Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
    ```

<details>
<summary>📷 Screenshot - Sysmon Installed & Logging</summary>

![Sysmon Install](https://github.com/user-attachments/assets/49689296-824d-402a-98a2-85339b9556e5)
![Sysmon Logs](https://github.com/user-attachments/assets/69e4bc39-6727-4931-a485-9eb6be50ca22)

</details>
