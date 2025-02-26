# Active-Directory-Home-Lab

## Objective

The Active Directory project aimed to establish a secure and monitored AD environment by deploying a domain controller, a Windows target machine, and an adversary machine. It involved implementing SIEM-based log analysis using Sysmon and Splunk, simulating attacks with Atomic Red Team and brute-force techniques, and analyzing logs to enhance threat detection and response capabilities.

### Skills Learned

- Practical experience in configuring and managing Active Directory environments.
- Hands-on experience in implementing and analyzing security event logs.
- Ability to simulate cyber attacks and assess detection capabilities.
- Proficiency in configuring and forwarding logs for security monitoring.
- Strong analytical skills in investigating security incidents and anomalies.

### Tools Used

- Sysmon – Implemented for advanced logging and endpoint monitoring.
- Splunk – Configured for log collection, forwarding, and security analysis.
- Atomic Red Team – Used to simulate real-world attack scenarios.
- Crowbar – Performed brute-force attacks on remote services.

### Network Diagram
![image](https://github.com/user-attachments/assets/8a450f85-3451-4fe0-83d9-3561e5cc086f)


The Active Directory (AD), Windows 10 client machine, Splunk server, and adversary machine are all on the same NAT network. The Active Directory hosts a domain named Hello.local, and the Windows 10 machine is joined to the domain using a domain user account. The Splunk server is configured as a SIEM, with Sysmon installed on both the Active Directory and Windows 10 machine for log enrichment. Logs are forwarded to the Splunk server via Splunk Universal Forwarder. The Parrot machine acts as an adversary to generate telemetry. Additionally, Atomic Red Team is installed on the Windows 10 machine to simulate various TTPs, allowing us to assess visibility and detection capabilities in our SIEM.

## Steps

### Step 1: Installing the Windows 10 Virtual Machine
In this project, VirtualBox is used as the hypervisor, but you can use any supported hypervisor you prefer.

Download the Windows 10 ISO from the official Microsoft website.

Next, create a new Virtual Machine and select the ISO image.

![Screenshot 2025-02-21 182715](https://github.com/user-attachments/assets/5ac577d2-2eb3-4b3b-95cd-ebc6aaa16e1e)

Check the 'Skip Unintended Installation' option and assign the hardware resources you want. For memory, it is recommended to allocate 4GB for better user experience.

![Screenshot 2025-02-21 184921](https://github.com/user-attachments/assets/6bcc9bbf-8ea6-4736-9169-6c1dbfb8e9f8)

Select Windows 10 Pro, so you will be able to connect to the domain and also perform other tasks, such as enabling RDP on this Windows device, etc.

![Screenshot 2025-02-21 185010](https://github.com/user-attachments/assets/051a5808-c1d6-4db7-a1af-aa10dbf169a8)

Check 'I don't have a product key' and proceed with the installation.

You have now successfully installed the Windows 10 Pro virtual machine.

### Step 2: Installing the Windows Server 2022 Virtual Machine
We are using Windows Server 2022 in this project, and you can download it from the official Microsoft site.

Now, create a new virtual machine and select the ISO image.

![Screenshot 2025-02-21 185111](https://github.com/user-attachments/assets/4ce1245b-edc5-4cd8-b0e0-df99997b1001)

Check 'Skip Unintended Installation' and assign the hardware resources you want. For memory, it is recommended to allocate 4GB for better user experience.

![Screenshot 2025-02-21 193158](https://github.com/user-attachments/assets/d922719f-d062-4227-afe7-19581e9af402)

Select Windows Server with Desktop Experience for the graphical user interface.

Proceed with the installation.

![Screenshot 2025-02-21 194134](https://github.com/user-attachments/assets/8b2f7edb-8435-4914-8197-f11cb45afbac)

You can provide the input key using this feature.

You have now successfully installed the Windows Server 2022 virtual machine.

### Step 3: Installing the Parrot OS Virtual Machine
You can also use Kali Linux as an alternative. Here, I am just going to download Parrot OS for the virtual machine and import the file to create the virtual machine.

You have now successfully installed the Parrot OS virtual machine.

### Step 4: Installing the Splunk Server

In this project, Ubuntu Server is used to configure the Splunk Server. You can download Ubuntu Server from the official site.

Now, create a new virtual machine, select the ISO image, skip unintended installation, and assign the hardware resources. It is recommended to allocate 8GB of RAM for this server, as the Splunk indexer requires significant resources to function smoothly.

Proceed with the Installation

### Step 5: Configuring the Network

We need to configure all the VMs to the same NAT network.

![image](https://github.com/user-attachments/assets/7b144ed7-79a9-445e-8f9f-7246cacc11e7)

We need to create a new NAT network using any private address range and name the network according to our preference.

![image](https://github.com/user-attachments/assets/52131323-20ba-41da-93d3-3a6a96f9c1ed)

Now, configure all the project’s virtual machines to the NAT network we created earlier.

### Step 6: Configuring the Splunk Server

### Assigning a Static IP Address
We are going to assign a static IP address to the Splunk server.

```
sudo nano /etc/netplan/50-cloud-init.yaml
```

Your filename might be different, so it’s best to first navigate to..
```
cd etc/netplan
```

Now list the files
```
ls
```

![image](https://github.com/user-attachments/assets/c04640bd-ac06-4bd7-9f96-4e5a87210705)

You will see a .yaml file; that's the file we want to configure

![image](https://github.com/user-attachments/assets/01a3231a-c83e-47b1-a12b-9e95fa98b698)

Assign the private IP address and configure all the essential details as mentioned above.

#### Downloading and Installing Splunk Enterprise

Now, download the Splunk Enterprise trial version on your host machine. Make sure to download it as a .deb file for Linux.

```
sudo apt update && sudo apt install virtualbox-guestadditions-iso && sudo apt install virtualbox-guest-utils
```

Install this on your Splunk server (Ubuntu Server). If you are using other hypervisors like VMware, refer to the official guide to learn how to share folders from your host to the virtual machine on that hypervisor.

![image](https://github.com/user-attachments/assets/e955759b-c2f8-49d6-a659-674d7c790e32)

Share the Splunk Enterprise trial version downloaded on your host with the Splunk server using the shared folder option in VirtualBox.

```
sudo reboot
```

Reboot the Splunk server.

```
sudo adduser <your_username> vboxsf
```

We need to add our user to the vboxsf group to access the shared folder that we created on our host for this virtual machine.

```
mkdir share
```

We are creating a folder named 'share' so we can mount the shared folder into this directory.

```
sudo mount -t vboxsf -o uid=1000,gid=1000, <shared-folder-name> share/
```

![image](https://github.com/user-attachments/assets/97c44ba2-e1fa-4dc1-b692-11978873f76f)

```
cd ./share
```

```
sudo dpkg -i <splunk_filename.deb>
```

![image](https://github.com/user-attachments/assets/176a26f6-159e-4bba-b9a4-2750e48be5c0)

```
cd /opt/splunk/bin
```

```
sudo -u splunk bash
```

```
./splunk start
```

Now, accept the license and configure the credentials.

```
exit
```

```
sudo ./splunk enable boot-start -user splunk
```

### Step 7 ~ Configuring Windows Server

#### Renaming the Host 

![image](https://github.com/user-attachments/assets/89f63b82-b4bc-4a37-ab50-dfb9c0030ccd)

#### Assigning a Static IP Address

![image](https://github.com/user-attachments/assets/1939b22d-3300-42fc-a3a2-ec65d2e29359)

Go to your Adapter Properties > Internet Protocol Version 4 > assign the static IP address.

#### Setting up Active Directory Domain Service

Open Server Manager, then:

![image](https://github.com/user-attachments/assets/aafd51f1-798a-4f2b-b94e-021ea7322950)

![image](https://github.com/user-attachments/assets/a03ac413-f0db-4f9c-98e9-54a6aff437ce)


In the Installation Type tab, make sure you select the first option.

![image](https://github.com/user-attachments/assets/a0a94944-4dd7-4c0b-835d-693645364709)

Select the Active Directory Domain Services for Server Roles and proceed with the installation.

#### Setting up Domain Controller

![image](https://github.com/user-attachments/assets/cd28be95-6407-41dd-8afb-24a21a33bbf8)

Click Manager (flag icon) in the Server Manager and click to promote it as Domain Controller.

![image](https://github.com/user-attachments/assets/fad27eed-eb07-4809-b52a-97407208ba39)

In here, the root domain name is `Hello.local`

Now, proceed with the installation and restart the Server

#### Creating Domain User Account

In the Server Manager tool, you will see this option:

![image](https://github.com/user-attachments/assets/ced6f5ba-e420-4862-9230-200f7eb85529)

Let's create a new Organization Unit, named IT, and add a user called Michael Jack with the username `Mick`.

![image](https://github.com/user-attachments/assets/c3d24212-2100-466b-a17d-50861e1e477e)

Also, create an Organization Unit named HR and add Valorant as a user.

![image](https://github.com/user-attachments/assets/3c68ec91-0ebb-4e0b-80ef-fedcbd9ff876)


#### Reach Splunk Server Web Interface and Configure Listening
Enter the Splunk server IP with the default port 8000 in the browser.

![image](https://github.com/user-attachments/assets/a5fa6cc7-8647-4951-8361-b748e93a0a18)

You can sign in with the credentials that you provided during Splunk installation on the Splunk server (Ubuntu Server).

Go to Settings > Forwarding and Receiving.

![image](https://github.com/user-attachments/assets/a9b3c92d-bae2-4727-8a9d-d64436c8dcb0)

In the Receive Data option, click Add New. Set the default port `9997` and save it.

![image](https://github.com/user-attachments/assets/4ca2e5c6-7b8b-41bd-8d68-734ac46adfc8)
  
Go to Settings > Indexes

Create a new index as `endpoint` and save it. You can name the index of your choice, but here I’m naming it `endpoint`.

#### Download and Install Splunk Forwarder

Use the same credentials you used for the Splunk Enterprise Free Trial on your host machine and download the Splunk Forwarder from the website.

Once the download is complete, install the Splunk forwarder.

![image](https://github.com/user-attachments/assets/30522815-33ec-45d2-ac82-70e66e766b6b)

During the installation process, make sure you configure the indexer to your Splunk Server instance with the default port of `9997`.

#### Downloading and Installing Sysmon

Download it from Sysinternals.

For Sysmon config, we are using Olaf's config file: https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml

Open PowerShell and navigate to the Sysmon executable directory.

```
.\Sysmon64.exe -i ..\sysmonconfig.xml
```

`sysmonconfig.xml` is the config file that we are mentioning. Now, accept the license agreement and install Sysmon.

#### Forwarding Sysmon and Windows Event Logs

Navigate to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`.

As you don't want to mess up your default `input.conf` file, create a new `input.conf` file in this directory and use it to forward logs.

```
[WinEventLog://Application]

index = endpoint

disabled = false

[WinEventLog://Security]

index = endpoint

disabled = false

[WinEventLog://System]

index = endpoint

disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]

index = endpoint

disabled = false

renderXml = true

source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

As we created the index as `endpoint`, I mentioned the index as endpoint. If you named it anything else, change it accordingly. Now, copy and paste it into the new `input.conf` file you created in the directory above.

Configure the Splunk Forwarder service to run as the Local System Account.

![image](https://github.com/user-attachments/assets/cc4427d9-9a77-42a6-999e-8fa6e38aa588)

Now stop and start the Splunk Forwarder service on the Windows server.

![image](https://github.com/user-attachments/assets/65fdb705-40c4-4de6-9f18-5ce8cf1b20d6)

Every time you make any changes to the Splunk Forwarder, make sure to restart the Splunk Forwarder service so that the changes are reflected on the Splunk server.

#### Enable RDP

Go to This PC > Properties > Advanced System Settings.

![image](https://github.com/user-attachments/assets/f17c469b-3e11-49d8-818d-3b4a2090151f)

![image](https://github.com/user-attachments/assets/f2e47ae8-2f23-414b-b4af-69b47f5c12e4)

Select Users and add users.

### Step 8 ~ Configuring Windows 10

#### Rename the Host
![image](https://github.com/user-attachments/assets/26f9915d-70fb-48c8-8d04-b503d07c7de7)

#### Assigning Static IP Address
![image](https://github.com/user-attachments/assets/df48dcbb-63ba-4ae4-9132-c5f1abb50db2)

Set the DNS address as the Domain Controller's IP address.

### Connecting Our Windows 10 Machine to the Domain

![image](https://github.com/user-attachments/assets/3277d276-8bc7-4c23-8158-fed20fe7a8aa)

![image](https://github.com/user-attachments/assets/d14bd2b5-7026-4fcb-a8aa-bff33bf6980d)

Enter the domain name here; in our case, `Hello.local`.

After changing that, click OK and restart the device.

Now, you can log in using the domain user credentials, and you will have successfully joined the domain.

#### Download and Install Splunk Forwarder

Use the same credentials you used for the Splunk Enterprise Free Trial on your host machine to download the Splunk forwarder from the website.

Once the download is complete, install the Splunk forwarder.

![image](https://github.com/user-attachments/assets/30522815-33ec-45d2-ac82-70e66e766b6b)

During the installation process, make sure you configure the indexer to your Splunk Server instance with the default port of `9997`.

#### Downloading and Installing Sysmon

Download it from Sysinternals.

For Sysmon config, we are using Olaf's config file: https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml

Open PowerShell and navigate to the Sysmon executable directory.

```
.\Sysmon64.exe -i ..\sysmonconfig.xml
```

`sysmonconfig.xml` is the config file we are referring to. Now, accept the license agreement and install Sysmon.

#### Forwarding Sysmon Logs and Windows Event Logs

Navigate to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`

As you don't want to mess up your default `input.conf` file, create a new `input.conf` file in this directory and use it to forward logs.

```
[WinEventLog://Application]

index = endpoint

disabled = false

[WinEventLog://Security]

index = endpoint

disabled = false

[WinEventLog://System]

index = endpoint

disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]

index = endpoint

disabled = false

renderXml = true

source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

As we created the index as `endpoint`, make sure to adjust the index if you named it something else. Now, copy and paste this configuration into the new `input.conf` file you created in the directory mentioned above.

Configure the SplunkForwarder Service to run as the Local System Account.

![image](https://github.com/user-attachments/assets/cc4427d9-9a77-42a6-999e-8fa6e38aa588)

Now, stop and start the SplunkForwarder Service on the Windows 10 Machine.

### Step 9 ~ Configuring the Parrot Machine and Bruteforcing RDP

#### Assigning a Static IP Address

```
nmcli connection modify "your_connection_name" ipv4.addresses 192.168.1.100/24
nmcli connection modify "your_connection_name" ipv4.gateway 192.168.1.1
nmcli connection modify "your_connection_name" ipv4.method manual
nmcli connection modify "your_connection_name" ipv4.dns "8.8.8.8 8.8.4.4"
```

Now, restart the connection.

```
nmcli connection down "your_connection_name" && nmcli connection up "your_connection_name"
```

#### Setting up the Environment
```
mkdir AD-Project
```

We will work on our attack in this folder to keep it organized.

#### Installing Crowbar
```
sudo apt update && sudo apt install crowbar
```

#### Getting Our Wordlist

```
cd /usr/share/wordlist
```

We can find the famous rockyou.txt password list, but it won't be enough to crack the password. From an attacker's perspective, they need to perform information gathering to acquire valid information about the target, and they will create a wordlist based on that information.

To simulate the attack, we will use the first 10 passwords from rockyou.txt and add the real password to the list.

```
head -n 10 /usr/share/wordlist/rockyou.txt > ~/AD-Project/passwords.txt
```

```
nano passwords.txt
```

Now, we can add the password to the list to successfully brute-force the user's RDP.

##### Bruteforcing Using Crowbar 

```
crowbar -b rdp -u Mick -C passwords.txt -s 10.0.2.16/32
```

![Screenshot 2025-02-25 113451](https://github.com/user-attachments/assets/5e555e40-80eb-463c-b7f9-5b5c568f6630)

We got the password, and now we can check the Splunk logs.

### Step 10 ~ Analyzing Bruteforce Attack Using Splunk

![Screenshot 2025-02-25 113143](https://github.com/user-attachments/assets/14302afd-ccb6-4ba3-be7a-88bb3dfc396a)

After searching for Windows EventCode 4625, which indicates a failed logon attempt, we can see many events occurring within 5 minutes. They all happened at the same time, which clearly indicates a brute-force attempt.

![Screenshot 2025-02-25 113222](https://github.com/user-attachments/assets/6c50a21e-32a6-43f8-a7b5-f31cb9fc8e6e)

If we look inside the logs, we can see that all the attempts were made from our Parrot host with the IP address 10.0.2.154. So, we can check if the brute-force attempt was successful by looking at EventCode 4624, which represents a successful logon event. 

![Screenshot 2025-02-25 113403](https://github.com/user-attachments/assets/1092453a-4248-442f-986e-c0a3753cfe87)

We can see one logon success from the attacker host, which indicates that the brute-force attempt was successful.

![Screenshot 2025-02-25 113429](https://github.com/user-attachments/assets/699f6e09-fcf8-4a00-a33e-157ddd7390fc)

### Step 11 ~ Installing Atomic Red Team on Windows 10 VM

#### Excluding a Directory

Open the Windows Security settings and exclude the entire C:\ drive.

![image](https://github.com/user-attachments/assets/a11dbbb5-f893-4cd9-94b0-c4db10dcdf9a)


![image](https://github.com/user-attachments/assets/9b112dde-ad1e-4b2f-9ac8-5619ff8ed51f)

Enter the Administrator credentials.

![image](https://github.com/user-attachments/assets/bc8b29ad-4083-47f4-8aab-c7a52d6678c1)

Open PowerShell as Administrator.

```
Set-ExecutionPolicy Bypass CurrentUser
```
```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -UseBasicParsing);
Install-Atomic RedTeam -getAtomics
```

Now you have installed Atomic Red Team on the Windows machine.

Using Atomic Red Team, you can generate telemetry from different TTPs (Tactics, Techniques, and Procedures).

You can refer to the MITRE ATT&CK Framework, as most techniques in that framework are included in Atomic Red Team. By performing those techniques, you can generate telemetry and analyze it in Splunk.

For example, let's execute the `T1136.001` sub-technique using Atomic Red Team.

![image](https://github.com/user-attachments/assets/46a1427d-77d5-48c3-b6bc-432640fa1926)

If we look at Splunk and investigate the logs, we can see the telemetry generated by this Windows 10 machine.

![Screenshot 2025-02-25 152721](https://github.com/user-attachments/assets/c753a875-4685-48f1-b7eb-5d9a7cd41170)

This is very useful because it helps develop investigation skills. Most techniques have detection methods in the MITRE ATT&CK Framework, so you can learn from them. Also, if no telemetry is generated, it highlights a visibility gap that can be addressed.



