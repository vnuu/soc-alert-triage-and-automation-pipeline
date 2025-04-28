# 🚨 SOC Alert Automation Pipeline

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
   
![image](https://github.com/user-attachments/assets/2d9c2ff8-adab-4eb7-892b-7e5dea98cf99)

#### 1.2 Create a New Windows 10 Virtual Machine
1. Open **VirtualBox** and click **New** to start creating a new VM.
2. Name the VM (e.g., "Windows10") and select **Windows 10** as the operating system version.
3. Allocate **4GB of RAM** (minimum) and **20GB of disk space** (recommended: 8GB RAM, 50GB disk).
4. Select **Create a virtual hard disk now** and choose **VDI (VirtualBox Disk Image)** format with **Dynamically allocated** storage.
5. Click **Create** to finalize the VM creation.
6. Select the Windows 10 Virtual Machine and click **Start** to run the VM.

![image](https://github.com/user-attachments/assets/506d1411-27de-4d89-bfc7-c055f131641e)

### 2. Installing Sysmon

**Sysmon** is installed to generate detailed Windows event logs like process creation, network connections, and file changes. In this project, it's used to capture security events when tools like Mimikatz are run, so Wazuh can detect them and automate responses through TheHive and Shuffle.

#### 2.1 Install Sysmon



