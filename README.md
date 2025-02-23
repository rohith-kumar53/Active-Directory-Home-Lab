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


### Step 5 ~ Configuring Windows Server

 


