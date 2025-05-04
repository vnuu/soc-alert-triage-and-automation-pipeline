# SOC Alert Automation Pipeline

A complete, end-to-end SOC alert triage pipeline that integrates Windows 10 telemetry (via Sysmon) with cloud-hosted SIEM, SOAR, and case management platforms to automate Mimikatz alert detection, enrichment, and escalation.

---

## Tools & Technologies

- **Windows 10 VM** with Sysmon
- **Wazuh** (SIEM)
- **Shuffle** (SOAR automation)
- **TheHive** (Case management)
- **VirusTotal API** (Reputation checking)
- Ubuntu 22.04 Cloud VMs for hosting Wazuh and TheHive servers

---

## Part 1: Windows 10 VM Installation and Configuration

### 1. Setting Up the Windows 10 Virtual Machine in VirtualBox

**VirtualBox** is a free and open-source virtualization tool that enables you to create and run virtual machines on your computer. Follow the steps below to create and configure a Windows 10 VM.

#### 1.1 Install VirtualBox
1. Download and install **VirtualBox** from [VirtualBox Downloads](https://www.virtualbox.org/wiki/Downloads).
2. Follow the installation instructions specific to your operating system (Windows, macOS, or Linux).

- **Virtualbox Downloads Page**
![image](https://github.com/user-attachments/assets/2d9c2ff8-adab-4eb7-892b-7e5dea98cf99)

#### 1.2 Create a New Windows 10 Virtual Machine
1. Open **VirtualBox** and click **New** to start creating a new VM.
2. Name the VM (e.g., "Windows10") and select **Windows 10** as the operating system version.
3. Allocate **4GB of RAM** (minimum) and **20GB of disk space** (recommended: 8GB RAM, 50GB disk).
4. Select **Create a virtual hard disk now** and choose **VDI (VirtualBox Disk Image)** format with **Dynamically allocated** storage.
5. Click **Create** to finalize the VM creation.
6. Select the Windows 10 Virtual Machine and click **Start** to run the VM.

- **Windows 10 Virtual Machine Running**
![image](https://github.com/user-attachments/assets/506d1411-27de-4d89-bfc7-c055f131641e)

### 2. Setting up Sysmon on Windows 10 VM 

**Sysmon** is installed to generate detailed Windows event logs like process creation, network connections, and file changes. In this project, it's used to capture security events when tools like Mimikatz are run, so Wazuh can detect them and automate responses through TheHive and Shuffle.

#### 2.1 Download Sysmon

1. Download Sysmon from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Click on the **Download Sysmon** link to download a ZIP file.
3. Extract the contents of the ZIP file to a folder, for example: `C:\Tools\Sysmon`
4. The extracted files should include:
     - `Sysmon.exe` (32-bit)
     - `Sysmon64.exe` (64-bit)
     - License agreement text file

#### 2.2 Download Sysmon Configuration File

1. Head to https://github.com/olafhartong/sysmon-modular
2. Open the repository and locate the file `sysmonconfig.xml`
3. Click the file, then click the **Raw** button
4. Right-click anywhere on the page and choose **Save As**
5. Save the file as `sysmonconfig.xml` in your Sysmon folder, e.g., `C:\Downloads\Sysmon`

- **The Sysmon folder should look like this:**

![image](https://github.com/user-attachments/assets/96ec249f-129b-476d-be6a-4aa09b07efa3)

#### 2.3 Running Sysmon via Powershell

1. Open Powershell as Administrator
2. In Powershell, navigate to the folder where Sysmon was located
```powershell
   cd "C:\Downloads\Sysmon"
```
3. Run Sysmon with the Configuration File
```powershell
   .\Sysmon64.exe -i sysmonconfig.xml
```
4. Verify that Sysmon is Running
```powershell
   Get-Service Sysmon64
```
5. Verify Sysmon logs in Event Viewer


