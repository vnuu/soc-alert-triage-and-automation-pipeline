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

## Part 1: Windows 10 VM and Sysmon Installation

### 1. Setting Up the Windows 10 Virtual Machine in VirtualBox

**VirtualBox** is a free and open-source virtualization tool that enables you to create and run virtual machines on your computer. Follow the steps below to create and configure a Windows 10 VM.

#### 1.1 Install VirtualBox
1. Download and install **VirtualBox** from the official website:  
   [VirtualBox Download](https://www.virtualbox.org/wiki/Downloads).
2. Follow the installation steps based on your operating system (Windows, macOS, or Linux).

#### 1.2 Create a New Windows 10 Virtual Machine
1. Open **VirtualBox** and click on the **New** button to create a new virtual machine.
2. In the dialog that appears, name your VM (e.g., “Windows10-SOC”), and select **Windows 10** as the version.
3. Allocate **at least 4GB of RAM** (8GB is recommended for better performance).
4. Choose **Create a virtual hard disk now** and allocate at least **20GB of storage**.
5. Select **VDI (VirtualBox Disk Image)** and choose **Dynamically allocated** storage for flexibility.
6. Click **Create** to finalize the VM creation.
