# Security Alert Automation Pipeline

**A complete, end-to-end SOC alert triage pipeline that integrates Windows 10 telemetry (via Sysmon) with cloud-hosted SIEM, SOAR, and case management platforms to automate Mimikatz alert detection, enrichment, and escalation.**

---

## Tools & Technologies

- **Windows 10 VM** with Sysmon
- **Wazuh** (SIEM)
- **Shuffle** (SOAR automation)
- **TheHive** (Case management)
- **VirusTotal API** (Reputation checking)

---

## Objectives

**The goal of this project is to design and implement a fully automated SOC alert triage pipeline that integrates endpoint telemetry (via Sysmon) with a cloud-hosted SIEM (Wazuh), SOAR automation (Shuffle), and case management (TheHive) platforms. The pipeline automates the detection, enrichment, and escalation of Mimikatz alerts in a controlled environment, simulating real-world attack scenarios.**

---

## Architecture Diagram

**This project uses Wazuh, TheHive, and Shuffle to automate threat detection and response. Logs from a Windows 10 machine are sent to the Wazuh Manager, which triggers alerts. These alerts are processed by Shuffle, which enriches the data, sends it to TheHive to create cases, and notifies the SOC analyst by email. Based on the analysis, Shuffle or the analyst can take response actions. The setup helps simulate a basic SOC workflow with automated detection, alerting, and response.**

![image](https://github.com/user-attachments/assets/4c02535d-074d-4b94-92d8-f2fbd2d292ef)

---

## Application and VM Setup

**In this phase, virtual machines were provisioned to host the core components of the SOC automation stack. This included setting up separate VMs for the Wazuh SIEM server and TheHive incident response platform. Supporting software and dependencies were also installed to ensure all components could run smoothly in an isolated lab environment.**

### 1. Windows 10 VM 

VirtualBox is used as the hypervisor to run the Windows VM locally.

- [VirtualBox Download](https://www.virtualbox.org/wiki/Downloads)
- VirtualBox Version: `7.x`
- Extension Pack: Installed (for additional features like clipboard sharing and USB passthrough)

To simulate real-world attacker and endpoint behavior, a dedicated Windows 10 virtual machine (VM) was created. This endpoint serves as the telemetry source in the lab, designed to generate logs and security events for collection, detection, and triage via Wazuh and TheHive.

**Virtual Machine Settings**

| Setting        | Value             |
|----------------|------------------|
| VM Name        | `WIN10-ENDPOINT` |
| OS Type        | Windows 10 (64-bit) |
| Memory         | 8 GB              |
| vCPUs          | 2                 |
| Disk Size      | 50 GB (Dynamic)   |
| Network        | NAT + Host-Only   |


![image](https://github.com/user-attachments/assets/02727a8e-094e-402e-b278-f144f774b610)


**Sysmon**

**Sysmon is installed to generate detailed Windows event logs like process creation, network connections, and file changes. In this project, it's used to capture security events when Mimikatz is run, so Wazuh can detect it and automate responses through TheHive and Shuffle.**

1. Download Sysmon from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Click on the **Download Sysmon** link to download a ZIP file.
3. Extract the contents of the ZIP file to a folder, for example: `C:\Tools\Sysmon`
4. The extracted files should include:
     - `Sysmon.exe` (32-bit)
     - `Sysmon64.exe` (64-bit)
     - License agreement text file

**Sysmon Configuration File**

1. Head to https://github.com/olafhartong/sysmon-modular
2. Open the repository and locate the file `sysmonconfig.xml`
3. Click the file, then click the **Raw** button
4. Right-click anywhere on the page and choose **Save As**
5. Save the file as `sysmonconfig.xml` in your Sysmon folder, e.g., `C:\Downloads\Sysmon`

- **The Sysmon folder should look like this:**

![image](https://github.com/user-attachments/assets/96ec249f-129b-476d-be6a-4aa09b07efa3)

**Running Sysmon**

1. Open Powershell as Administrator
2. In Powershell, navigate to the folder where Sysmon was located
```powershell
   cd "C:\Downloads\Sysmon"
```
3. Run Sysmon with the Configuration File
```powershell
   .\Sysmon64.exe -i sysmonconfig.xml
```
![image](https://github.com/user-attachments/assets/49689296-824d-402a-98a2-85339b9556e5)

4. Verify that Sysmon is Running
```powershell
   Get-Service Sysmon64
```
![image](https://github.com/user-attachments/assets/faf6c6a5-9148-4493-be8b-ecb05b097591)

5. Verify Sysmon logs in Event Viewer

- Go to:
```Settings
   Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```
![image](https://github.com/user-attachments/assets/69e4bc39-6727-4931-a485-9eb6be50ca22)


### 2. Wazuh and TheHive

**In this part of the project, two cloud-based virtual machines (VMs) were set up on DigitalOcean, one hosting Wazuh for SIEM and the other hosting TheHive for case management. They were securely configured to communicate with each other, with only the necessary ports open through firewall rules.**

### Wazuh and TheHive VM Setup

1. Sign up for a DigitalOcean account.

2. Create New Droplets (VMs)
- Go to your DigitalOcean dashboard and click on **Create** → **Droplets**.
- Choose an image (for both VMs, select Ubuntu 22.04 (LTS) x64 as the base image).
- Select a plan.
- Set up authentication (either SSH keys or password).
- Click on **Create Droplet**.

![image](https://github.com/user-attachments/assets/7b1aec42-5728-4b3e-bb04-52a4cf40f3f1)


3. Configure Firewall
Once the VMs are created, navigate to **Networking** in the DigitalOcean dashboard and set up firewall rules to ensure that only necessary ports are accessible for both VMs.

**Inbound Rules:**
Allow only your IP address to access all necessary ports over both TCP and UDP protocols. This restricts unauthorized access while enabling full control from your machine.

- **Protocol**: TCP & UDP  
- **Port Range**: All  
- **Source**: Your IP address (e.g., your home or office public IP)

![image](https://github.com/user-attachments/assets/42e39223-e9ca-43e4-87ea-465141d51374)


**Outbound Rules:**
Permit full outbound access to enable the VMs to reach external services.

- **ICMP**: All destinations (for ping and diagnostics)  
- **TCP/UDP**: All ports to all IPv4 and IPv6 destinations

![image](https://github.com/user-attachments/assets/cb3cd518-f739-46d4-8419-6d5b571666e3)

### Wazuh 4.7 Installation

1. Use SSH to connect to the Wazuh VM using the public IP.
```bash
ssh root@your-wazuh-vm-ip
```

2. Update and Upgrade VM
```bash
apt-get update && apt-get upgrade 
```

3. Install Wazuh Manager
- On the Wazuh VM, run the necessary installation commands:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
- Extract Wazuh Credentials **(Be sure to take note of the credentials. These will be used to log into the Wazuh Dashboard)**
```bash
sudo tar -xvf wazuh-install-files.tar
```

![wazuhinstall](https://github.com/user-attachments/assets/ad7df9bc-0f36-4a98-83c8-8fbf94a65326)

4. Start and Enable Wazuh service
- Start Wazuh:
```bash
systemctl start wazuh-manager
```
- Enable Wazuh to start on boot:
```bash
systemctl enable wazuh-manager
```
- Check that Wazuh is running:
```bash
systemctl status wazuh-manager
```
![image](https://github.com/user-attachments/assets/8635aa1a-80c2-4e92-b6bb-1b1f9c9ff96b)

### TheHive 5 Installation

1. Use SSH to connect to TheHive VM using the public IP.
```bash
ssh root@your-thehive-vm-ip
```

2. Update and Upgrade VM
```bash
apt-get update && apt-get upgrade 
```

3. Install Dependencies
```bash
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
```

![dependencies](https://github.com/user-attachments/assets/3b295ee8-ef9d-49da-927e-126c4d3d8ab3)

4. Install Java
```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```
![verifyjava](https://github.com/user-attachments/assets/16625625-c401-4a30-8889-2f2db8887b77)

5. Install Cassandra
```bash
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

6. Install Elasticsearch
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

7. Install TheHive
```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

---

## Wazuh and TheHive Configuration

**Wazuh was configured as the SIEM solution to detect potential security events based on predefined rules. TheHive was set up to receive alerts from Wazuh via webhooks. This integration ensures that once Wazuh detects suspicious activity, a case is automatically created in TheHive for further analysis and incident management.**

### TheHive 5 Configuration

After installing TheHive, perform the following steps to configure it properly and ensure it's ready to receive alerts and integrate with other tools like Wazuh or Cortex.

**Cassandra Configuration**

1. Locate Cassandra's configuration file
```bash
nano /etc/cassandra/cassandra.yaml
```

2. Configure `cluster_name`
```bash
cluster_name: 'vnu'
```
**Replace 'vnu' with your desired cluster name to ensure it matches the Cassandra cluster configuration.**

3. Set listen_address and `rpc_address` as the public IP of TheHive
- Listen Address:
```bash
listen_address: 209.97.173.238
```

- RPC Address:
```bash
rpc_address: 209.97.173.238
```

4. Configure seed provider
```bash
seeds: "209.97.173.238:7000"
```

5. Save configuration and stop the Cassandra service
```bash
systemctl stop cassandra.service
```

6. Remove old Cassandra files
```bash
rm -rf /var/lib/cassandra/*
```

7. Start Cassandra service
```bash
systemctl start cassandra.service
```

8. Ensure Cassandra service is running
```bash
systemctl status cassandra.service
```

**Elasticsearch Configuration**

1. Locate Elasticsearch's main configuration file
```bash
nano /etc/elasticsearch/elasticsearch.yml
```

2. Configure `cluster.name`
```bash
cluster.name: vnu
```

3. Configure `node.name` (Uncomment and set the node.name parameter)
```bash
node.name: node-1
```

4. Configure `network.host`
```bash
network.host: 209.97.173.238
```

5. Configure `cluster.initial_master_nodes`

(To start Elasticsearch, you must configure either a discovery seed host or specify an initial master node. For this project, the cluster.initial_master_nodes setting is used to define the initial master node.)
```bash
cluster.initial_master_nodes: ["node-1"]
```

6. Save configuration and start Elasticsearch service
```bash
systemctl start elasticsearch
```

7. Enable Elasticsearch service
```bash
systemctl enable elasticsearch
```

8. Ensure Elasticsearch service is running
```bash
systemctl status elasticsearch
```

**TheHive Configuration**

1. Ensure TheHive user and group has access to `/opt/thp`
```bash
chown -R thehive:thehive /opt/thp
```

![image](https://github.com/user-attachments/assets/7487ab49-b474-459d-80e3-40efb697f7bc)

2. Locate TheHive configuration file
```bash
nano /etc/thehive/application.conf
```

3. Configure database and index configuration

![image](https://github.com/user-attachments/assets/165d16a8-44cf-412e-a2ce-957e2a807185)

4. Configure service configuration

![image](https://github.com/user-attachments/assets/e5de8473-5bd6-4f24-ba5b-06d1454d2f25)

5. Start and enable TheHive service
```bash
systemctl start thehive
```

```bash
systemctl enable thehive
```

6. Ensure that all 3 services are running

![checkallservices](https://github.com/user-attachments/assets/d8fc9ed8-c893-4968-bcf7-b6a62177c4d3)

7. Log into TheHive's dashboard with the default credentials
- TheHive Login Screen

![image](https://github.com/user-attachments/assets/1ee0c663-94b0-4ef3-9f96-ca663d8cbb6d)

- TheHive Dashboard

![image](https://github.com/user-attachments/assets/595f05f4-6455-4881-8c7e-d9fa88430ec3)


### Wazuh 4.7 Configuration

1. Log into Wazuh Dashboard with the administrative credentials.
- Wazuh Login Screen
  
![wazuhlogin](https://github.com/user-attachments/assets/014779c8-0058-4848-8b94-fb42f24132ce)

- Wazuh Dashboard
  
![wazuhdashboard](https://github.com/user-attachments/assets/b4333f7e-9771-4d51-811c-672db0102aaf)

2. Install Wazuh Agent on Windows 10 VM
- In the Wazuh Dashboard, click on "Add agent"
- Select the Windows package
- Set the server address as Wazuh's public IP
- Assign an agent name (Optional)
- Copy the commands and run them with Powershell on the Windows 10 VM
- Start the wazuh agent service:
```powershell
NET START WazuhSvc
```
- Check for the agent in the Wazuh dashboard

![wazuh agent installed](https://github.com/user-attachments/assets/13133e77-a3c8-4a7f-ae99-54ebe3d13a22)

---

## Telemetry Generation and Ingestion

**In this part, simulated attack activities were carried out on the Windows 10 virtual machine to produce telemetry data. **Mimikatz** is used to mimic credential theft techniques often seen in real-world attacks. The purpose was to evaluate Wazuh’s detection capabilities by observing how it reacts to suspicious behavior. The Windows VM was configured to forward logs to the Wazuh manager. Wazuh’s built-in ruleset was used to identify malicious patterns in the logs. Once the logs were ingested, alerts were generated and made available for further processing and correlation with TheHive.**

### Sysmon Log Ingestion

1. On the Windows 10 VM, locate the `ossec.conf` file
```file
C:\Program Files (x86)\ossec-agent
```
2. For good measure, create a backup of the `ossec.conf` file
3. Configure the `ossec.conf` file to allow it to ingest Sysmon logs:
```text
<localfile>
   <location>Microsoft-Windows-Sysmon/Operational</location>
   <log_format>eventchannel</log_format>
</localfile>
```
4. Save the configuration and restart the Wazuh service.
5. Head to the Wazuh Dashboard and check for Sysmon events. (Note: It may take some time for the Sysmon events to load.)

![image](https://github.com/user-attachments/assets/ba427250-86be-45d8-894e-46a858f53535)

### Wazuh Manager Log Ingestion Configuration

1. In Wazuh Manager, ensure that a backup of `ossec.conf` is made
```bash
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```

2. In `ossec.conf`, set the following parameters to `yes`
```nano
<logall>yes</logall>
<logall_json>yes</logall_json>
```

3. Save the configuration and restart the Wazuh Manager service.
4. Check for the archived logs called `archives.json` and `archives.log`:
```bash
cd /var/ossec/logs/archives/
```

4. Open the `filebeat.yml` file to configure Wazuh to ingest these logs.
```bash
nano /etc/filebeat/filebeat.yml
```

5. In the `filebeat.modules` section, set the `archives` parameter to `true`

![image](https://github.com/user-attachments/assets/848068a9-51ab-4755-8a68-a398585f00c4)

6. Save the configuration and restart the Filebeat service.

### Wazuh Index Creation

1. On the Wazuh Dashboard, under the "Management" section in the sidebar menu, click on "Stack Management" and then select "Index Patterns".
2. Create an index pattern and name it as `wazuh-archives-**`.
3. Select `timestamp` for the time field and click on the `Create index pattern` button.

![image](https://github.com/user-attachments/assets/87bc2357-6d8f-48ef-9067-c926abbde990)

4. Head to "Discover" and change the index pattern to the archives to view the events.

![image](https://github.com/user-attachments/assets/45b889ee-7a6f-4878-9f06-fe999b647df9)


### Mimikatz Testing

1. On the Windows 10 VM, download and extract [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919) (Note: Ensure Windows Defender or other security software is disabled, or add exclusions, as Mimikatz may be flagged as malware.).
2. Run Powershell as Administrator and run Mimikatz.
- Head to Mimikatz installed directory.
- Run `Mimikatz.exe`.

![mimkatzexe](https://github.com/user-attachments/assets/048beaba-fd23-4faf-830c-d0c38e14f76c)

3. In Discover, query for Mimikatz in the search bar. Mimikatz event logs should now be shown. 

![image](https://github.com/user-attachments/assets/51ae2604-c8a9-4e50-b3c3-17ab851ee1e7)

**Troubleshooting**

- If alerts do not appear immediately, rerun the binary multiple times or verify log ingestion using the following command
```bash
cat /var/ossec/logs/archives/archives.log | grep -i mimikatz
```

![image](https://github.com/user-attachments/assets/2838ef99-de58-4096-beee-5d3c39530fe8)

- If Mimikatz is still not showing in Wazuh but its appearing in `archives.log`, try forcing ingestion by restarting the Wazuh Manager service **(NOTE: Only do this in a demo environment, not in production)**


### Rule Creation

1. On the homepage, select Management, then under Administration, click on Rules.
2. Click on Manage Rule Files at the top right corner.
3. Click on Custom Rules.
4. Click on the edit icon for `local_rules.xml`.
5. Add a custom rule for Mimikatz:
- Start by creating a `<rule>` tag and assign a unique `id`. Avoid using IDs that are already in use — custom rules often start from 100000 onwards.
- Set the `level` to define the severity of the event.  
- Inside the rule, use `<if_group>` to specify the group of logs it applies to. In this case, it would be `sysmon_event1`.
- Add a `<field>` to specify the condition. Use the `win.eventdata.originalFileName` field and a case-insensitive regular expression `(pcre2)` to match `mimikatz.exe`. ( `win.eventdata.originalFileName` is used because it reflects the original name of the binary, which stays the same even if the attacker renames the file.)
- Write a short and clear `<description>` to indicate what the rule detects — for example, "Mimikatz usage detected".
- Add a `<mitre>` tag and include the relevant MITRE ATT&CK technique ID — for Mimikatz, this is T1003 (Credential Dumping).
- Ensure the rule block is structured and indented properly.
- The rule block for Mimikatz should look like this:
```xml
 <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz usage detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
 </rule>
```
6. Save the XML file and restart Wazuh when prompted.
7. Rerun `Mimikatz.exe` on the Windows 10 VM and refresh the Wazuh Dashboard.
8. The Mimikatz alert should now been shown in the Security Events section:

![image](https://github.com/user-attachments/assets/152e5330-b031-4b61-8f8a-217401ef950b)


## SOAR Integration & Alert Automation

Shuffle, an open-source SOAR tool, was integrated into the environment to automate alert handling. When Wazuh detects an alert, it is forwarded to TheHive via Shuffle. An automated workflow was created to send email notifications to a designated SOC analyst.

**Webhook Configuration**

1. Create a New Workflow
- Log in to [Shuffle](https://shuffler.io/).
- Go to the **Workflows** tab.
- Click **"Create Workflow"**.
- Enter the workflow details.

2. Add Webhook Trigger
- From the **Workflow starters** section, drag the **Webhook** block into the canvas.
- Click on the block and set the **Name** to `Wazuh-Alerts`.
- Select **Environment** as `cloud`.
- Copy the **Webhook URI** (This is the endpoint Wazuh will send alerts to).

3. Ensure the action in the "Change Me" icon is set to "Repeat back to me" and the "Call" is set to "$exec"
4. SSH into Wazuh Manager and open the `ossec.conf` file.
5. In `ossec.conf`, place the integration tag and add the Shuffle URL in the `hook_url` tag.
```bash
  <integration>
    <name>shuffle</name>
    <hook_url>(Add URL Here) </hook_url>
    <rule_id>100002</rule_id>
    <alert_format>json</alert_format>
  </integration>
```
6. Restart the Wazuh manager.
7. Rerun Mimikatz on the VM.
8. Head to the Shuffle instance, click on the Webhook and click "Start" in the "Parameters" section.
9. Run the Workflow and click on the "Show Executions" button.

*The execution argument for the Webhook should show details on the Mimikatz alert generated by Wazuh:*

![shufflealert](https://github.com/user-attachments/assets/ac16cccf-fde6-41af-a5c0-f0d58f8319a4)

**Regex Capture**

1. Click on "Change Me" and set the name to "SHA256 Regex".
2. Set the action to "Regex capture group".
3. For the input, select the `hashes` field from the Execution Argument section. The input should look like this:
```
$exec.text.win.eventdata.hashes
```
3. Set the Regex pattern to parse the SHA256 value:
```regex
SHA256=([0-9A-Fa-f]{64})
```
4. Save and rerun the workflow.

*The SHA256 hash should now be parsed:*

![regex](https://github.com/user-attachments/assets/2bb5f807-28dd-4ebd-8b25-c9676ca4dabb)

**Virustotal Reputation Check**

1. Create an account for [Virustotal](https://www.virustotal.com/gui/home/upload) and obtain the API key.
2. On Shuffle, search for "Virustotal" and select it.
3. Select and drag "Virustotal" and place it on the workflow.
4. Set the action to "Get a hash report". (Ensure Virustotal is fully activated and refresh the workflow to see the actions.)
5. Authenticate Virustotal by pasting in the obtained API key.
6. Set the "Id" as the regex output:
```hash
$sha256_regex.group_0.#
```
7. Save and rerun the worflow.

*The hash file report should then be generated by Virustotal:*

![image](https://github.com/user-attachments/assets/b8c5086f-701a-4e7d-ba7d-2393914a1b5c)

*Last Analysis Stats:*

![image](https://github.com/user-attachments/assets/f14c6c0c-f9b9-4cf5-b8c9-c69a68df2fb9)

**TheHive Alert Creation**

1. Select "TheHive" in the apps section and drag it to the workflow.
2. Head to TheHive's dashboard and login using the default credentials.
3. On the dashboard, click on the "+" button on the top left and create an organization.
4. Select the organization and add two users under the profile of "analyst":
- Set the first user's Type as "Normal". Then, click on "Preview" and set the user's password.
- Set the second user's Type as "Service". Then, click on "Preview", create an API key for this user and copy it.

![image](https://github.com/user-attachments/assets/f58345ca-f1b6-4cbe-949d-48f269635c66)

5. Log out of the admin account and log into TheHive using the credentials of the first created user.
6. On Shuffle, click on TheHive and select the "+" button next to Authenticate.
7. Authenticate TheHive by copying over the generated API key.
8. Under URL, type in the public IP of TheHive instance and click "Submit".
9. Click on "Advanced" and modify the body of TheHive for the alert generation. Below is an example:
```
{
  "description": "Mimikats Detected on host: $exec.text.win.system.computer",
  "flag": false,
  "pap": 2,
  "time": "$exec.text.win.eventdata.utcTime",
  "title": "$exec.title",
  "host": "$exec.text.win.system.computer",
  "severity": 2,
  "source": "Wazuh",
  "sourceRef": "Rule 100003",
  "summary": "Mimikatz detected on host: $exec.text.win.system.computer ProcessID: $exec.text.win.system.processID CommandLine: $exec.text.win.eventdata.commandLine",
  "tags": ["T1003"],
  "title": "Mimikatz Detected",
  "tlp": 2,
  "type": "internal"
}
```

10. Save the workflow.
11. On DigitalOcean, create a custom firewall rule to allow inbound traffic from all ports under UDP protocol:

![image](https://github.com/user-attachments/assets/42f0904f-0684-46cb-8ec4-e04dd71daa6a)

12. Rerun the workflow.

*TheHive should now be able to generate alerts on Mimikatz:*

![image](https://github.com/user-attachments/assets/1a5bc486-3737-4415-bbbf-a16758faf4aa)

*Alert generated on TheHive dashboard:*

![image](https://github.com/user-attachments/assets/200e35d3-2d0c-4738-9721-631a6b1ee83f)

**Alert Generation via Email**

1. Drag the email application to the workflow and connect it to Virustotal.
2. Enter a valid email address in the "Recipients" section.
3. Enter a subject (Ex. "Mimikatz Detected!")
4. Set the body of the alert to include the time, title and the host of the alert.
```body
Time: $exec.text.win.eventdata.utcTime
Title: $exec.title
Host: $exec.text.win.system.computer
```
5. Save and rerun the workflow.

*The Mimikatz alert should now be sent via email:*

![email_shuffle](https://github.com/user-attachments/assets/0d893133-4898-475e-8702-9c5f1397139f)

*Analyst POV:*

![emailalert](https://github.com/user-attachments/assets/831eea81-62a0-4d47-974f-0a812662742a)

## Summary & Skills Gained

The project involved deploying a Windows 10 VM to simulate credential dumping via Mimikatz, with Wazuh configured for Sysmon log ingestion and custom detection rules to identify malicious activity. Alerts were forwarded using Filebeat to TheHive, where Shuffle automated alert enrichment with VirusTotal API integration. This environment enabled hands-on experience in developing detection logic, SIEM-to-SOAR integration, and automated incident response workflows typical of modern SOC operations.

**Skills Learned:**
- Sysmon configuration and event log analysis for attack detection  
- Crafting custom Wazuh rules for behavioral anomaly detection  
- Configuring Filebeat for reliable log forwarding to SIEM  
- SOAR orchestration with Shuffle to automate alert triage and enrichment  
- API integration for threat intelligence (VirusTotal) within incident workflows  
- End-to-end SIEM-SOAR pipeline implementation for SOC automation  
- Practical detection and response to credential dumping techniques  







