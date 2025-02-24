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
![Screenshot 2025-02-21 180550](https://github.com/user-attachments/assets/68d8fb15-b8f8-424f-8ca6-d8014fde4243)

The Active Directory (AD), Windows 10 client machine, Splunk server, and adversary machine are all on the same NAT network. The Active Directory hosts a domain named Hello.local, and the Windows 10 machine is joined to the domain using a domain user account. The Splunk server is configured as a SIEM, with Sysmon installed on both the Active Directory and Windows 10 machine for log enrichment. Logs are forwarded to the Splunk server via Splunk Universal Forwarder. The Parrot machine acts as an adversary to generate telemetry. Additionally, Atomic Red Team is installed on the Windows 10 machine to simulate various TTPs, allowing us to assess visibility and detection capabilities in our SIEM.

## Steps

### Step 1 ~ Installing Windows 10 Pro Virtual Machine
In this project Virtual box is used as the hypervisor but you can use any supported hypervisor you want. 

Download the Windows 10 iso from the official Microsoft site.

Now create a new Virtual Machine then select the iso image.

![Screenshot 2025-02-21 182715](https://github.com/user-attachments/assets/5ac577d2-2eb3-4b3b-95cd-ebc6aaa16e1e)

Check the Skip Unintended installation and assign the hardware resources you want, for memory, it is recommended to assign 4gb as Memory for better user experience.

![Screenshot 2025-02-21 184921](https://github.com/user-attachments/assets/6bcc9bbf-8ea6-4736-9169-6c1dbfb8e9f8)

Select Windows 10 pro, so only you can able to connect to the domain and also you can perform other features like enabling rdp on this windows device, etc.

![Screenshot 2025-02-21 185010](https://github.com/user-attachments/assets/051a5808-c1d6-4db7-a1af-aa10dbf169a8)

check I don't have a product key and proceed with the installation.

Now you have succesfully Installed Windows 10 pro Virtual Machine.


### Step 2 ~ Installing Windows Server 2022 Virtual Machine
We are using Windows Server 2022 Version in this Project, you can download this from the official Microsoft site.

Now create a new Virtual Machine then select the iso image.

![Screenshot 2025-02-21 185111](https://github.com/user-attachments/assets/4ce1245b-edc5-4cd8-b0e0-df99997b1001)

Check the Skip Unintended installation and assign the hardware resources you want, for memory, it is recommended to assign 4gb as Memory for better user experience.

![Screenshot 2025-02-21 193158](https://github.com/user-attachments/assets/d922719f-d062-4227-afe7-19581e9af402)

Select the Windows Server with Desktop Experience for Graphical User Interface.

Proceed with the Installation.

![Screenshot 2025-02-21 194134](https://github.com/user-attachments/assets/8b2f7edb-8435-4914-8197-f11cb45afbac)

You can provide the Input key using this feature.

Now you have succesfully Installed Windows 10 Server 2022 Virtual Machine.


### Step 3 ~ Installing Parrot OS Virtual Machine
You can also use Kali Linux Alternatively. In here I am just gonna download the parrot OS for the Virutal Machine and Import the file to create the Virtual Machine.

Now you have succesfully Installed Parrot OS Virtual Machine.


### Step 4 ~ Installing Splunk Server

In this project Ubunut Server is used to Configured Splunk Server. You can download the Ubuntu Server from the official site.

Now create a new Virtual Machine then select the iso image, Skip unintended installation and assign the Hardware resource. it is recommended to assign 8GB ram for this server because the splunks indexer need so much resources in order to work smoothly.

Proceed with the Installation


### Step 5 ~ Configuring Network

We need to Configure all the VM to the Same NAT Network.

![image](https://github.com/user-attachments/assets/7b144ed7-79a9-445e-8f9f-7246cacc11e7)

We need to create a new NAT Network using with any private address ranges and naming the network according to our choice.


![image](https://github.com/user-attachments/assets/52131323-20ba-41da-93d3-3a6a96f9c1ed)

Now configure all the Projects Virtual Machine to the NAT Network we created before.


### Step 6 ~ Configuring Splunk Server

### Assigning Static Ip Address
We are going to assign a static ip address to the Splunk Server.

```
sudo nano /etc/netplan/50-cloud-init.yaml
```

your filename might be different so it is best to first get into 
```
cd etc/netplan
```

Now list the files
```
ls
```

![image](https://github.com/user-attachments/assets/c04640bd-ac06-4bd7-9f96-4e5a87210705)

You will see a `.yaml` file, so that's the file we want to configure. 

![image](https://github.com/user-attachments/assets/01a3231a-c83e-47b1-a12b-9e95fa98b698)

Assign the Private ip address and configure all the essential details. Refer above.

#### Download and Installing Splunk Enterprise

Now Download the Splunk Enterprise trial version on your host Machine. Make sure you download it as `.deb` file for linux.

```
sudo apt update && sudo apt install virtualbox-guestadditions-iso && sudo apt install virtualbox-guest-utils
```


Install this in your Splunk Server (Ubuntu Server). If you are using other Hypervisors like Vmware then refer the official page guide to find how to share folders from your host to the Virtualmachine on that hypervisor.

![image](https://github.com/user-attachments/assets/e955759b-c2f8-49d6-a659-674d7c790e32)

Share the splunk Enterprise trial version downloaded on your host to the Splunk Server using the Shared folder option in Virtual box. 

```
sudo reboot
```

Reboot the Splunk Server.

```
sudo adduser <your_username> vboxsf
```

We need to add our user to the vboxsf group to access the share that we created on our host to this Virtual Machine.

```
mkdir share
```

We are creating a folder named share so we can mount the share into this folder

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

Now accept the license and configure the credentials.

```
exit
```

```
sudo ./splunk enable boot-start -user splunk
```

### Step 7 ~ Configuring Windows Server

#### Renaming the Host 

![image](https://github.com/user-attachments/assets/89f63b82-b4bc-4a37-ab50-dfb9c0030ccd)

#### Assigning Static Ip Address

![image](https://github.com/user-attachments/assets/1939b22d-3300-42fc-a3a2-ec65d2e29359)

Go to your Adapter Properties > Internet Protocol Version 4 > assign the static ip address

#### Setting up Active Directory Domain Service

Open Server Manager, then:

![image](https://github.com/user-attachments/assets/aafd51f1-798a-4f2b-b94e-021ea7322950)

![image](https://github.com/user-attachments/assets/a03ac413-f0db-4f9c-98e9-54a6aff437ce)


In the Installation Type tab, Make sure you select the first option

![image](https://github.com/user-attachments/assets/a0a94944-4dd7-4c0b-835d-693645364709)

Select the Active Directory Domain Services for Server Roles and proceed with the installtion.

#### Setting up Domain Controller

![image](https://github.com/user-attachments/assets/cd28be95-6407-41dd-8afb-24a21a33bbf8)

 Click Manager(flag icon) in the server manager and click promote it as Domain controller.

![image](https://github.com/user-attachments/assets/fad27eed-eb07-4809-b52a-97407208ba39)

In here, the root domain name `Hello.local`

Now proceed with the installation and restart the Server

#### Reach Splunk Server Web Interface and Configure Listening
enter the splunk server ip with the default port 8000 in the browser

![image](https://github.com/user-attachments/assets/a5fa6cc7-8647-4951-8361-b748e93a0a18)

You can sign in with the credential that you provided during splunk installation on the splunk server (Ubuntu Server).

Go to Settings > Forwarding and Receiving 

![image](https://github.com/user-attachments/assets/a9b3c92d-bae2-4727-8a9d-d64436c8dcb0)

In the Receive data option click Add new. Set the default port `9997` and save it.

![image](https://github.com/user-attachments/assets/4ca2e5c6-7b8b-41bd-8d68-734ac46adfc8)
  
Go to Settings > Indexes

Create New Index as `endpoint` and save it. You can name the Index of your choice that make sense but in here I am gonna name it as `endpoint`. 
#### Download and Install Splunk Forwarder

Use the same credential you used for the Splunk Enterprise Free trial on your host Machine in here also and download the Splunk forwarder from the website.

Once download it complete. Now Install the Splunk forwarder.

![image](https://github.com/user-attachments/assets/30522815-33ec-45d2-ac82-70e66e766b6b)
During the Installation Process, Make sure you configure the indexer to your Splunk Server instance with the default port of `9997`

#### Downloading and installing Sysmon

Downlaod it from the Sysinternals.

For sysmon config, we are using olafs config file
https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml

Open Powershell and locate into the sysmon executable directory

```
.\Sysmon64.exe -i ..\sysmonconfig.xml
```

`sysmonconfig.xml`, this is the config file that we are mentioning. Now accept the license agreement and install the sysmon. 

#### Forwarding Sysmon and Windows Event Logs

locate into `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`

As you don't want to mess up your default `input.conf` file, we are creating a new `input.conf` file in this directory and using it to forward logs.

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

As we created the index as `endpoint`, I mentioned the index as endpoint but if you named it anythign else then change it accordingly. Now copy it and paste it in the new `input.conf` file that you created in the above mentioned directory.

Configure the SplunkForwarder Service to run as Local System Account.
![image](https://github.com/user-attachments/assets/cc4427d9-9a77-42a6-999e-8fa6e38aa588)

Now stop and start the SplunkForwarder Service in the Windows 10 Pro Machine.

![image](https://github.com/user-attachments/assets/65fdb705-40c4-4de6-9f18-5ce8cf1b20d6)

Everytime you make any changes to the SplunkForwarder, Make sure you restart the SplunkForwader service then only the changes will be reflected on the Splunk Server.

### Step 8 ~ Configuring Windows 10

#### Rename the Host
![image](https://github.com/user-attachments/assets/26f9915d-70fb-48c8-8d04-b503d07c7de7)

#### Assigning Static Ip Address
![image](https://github.com/user-attachments/assets/e3c4c5d3-8f15-4b4e-bed1-4bc4cf75937d)

### Setting up the Domain

