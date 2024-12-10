# JKZH-Honeypot Project (EZ-Honeypot)

## What have I learned? 

Through this honeypot project, I gained hands-on experience in deploying and managing cloud-based security environments using Vultr and Ubuntu Linux, with a focus on system hardening and secure configurations. I developed expertise in setting up multi-honeypot environments with TPOT, capturing real-world attack data, and using the ELK Stack for network traffic monitoring and log analysis. By simulating real-world attack vectors and analyzing threats, I’ve sharpened my skills in intrusion detection, malware analysis, and incident response. This project has prepared me for a cybersecurity role by providing practical knowledge of cloud security, threat monitoring, and hands-on experience in identifying and mitigating cyber threats. I called this honeypot project EZ-Honeypot. 

Thank you for following along,

-Jonathan

## Objective
- The honeypot project focused on creating a controlled environment to simulate and monitor cyberattacks using various honeypot technologies. The primary goal was to deploy a decoy system that attracted malicious activity, capturing detailed logs of attacker behavior, including tactics, techniques, and malware interactions. This hands-on setup provided valuable insight into emerging threats, helping to refine detection strategies and improve network defenses. By analyzing the captured data, the project enhanced my understanding of attack vectors and supported the development of proactive security measures.

### Skills Learned

- #### Cyber Threat Intelligence Collection: 
Gained hands-on experience in collecting and analyzing attack data to identify emerging threats and adversarial tactics.
- #### Security Monitoring and Analysis: 
Developed my skills in monitoring and analyzing honeypot logs to detect and understand malicious activity and attack patterns.
- #### Cloud Infrastructure Management: 
Learned how to deploy, scale, and manage honeypots in cloud environments like Vultr for flexible and scalable threat simulation.
- #### Firewall Configuration and Network Security: 
Configured firewalls and additional network defenses to simulate vulnerable systems and capture realistic attack data.
- #### Incident Response: 
Improved incident response capabilities by analyzing real-world attack scenarios, identifying indicators of compromise, and developing effective mitigation strategies.

### Tools Used

- Vultr: I deployed and managed a virtual private server to host honeypots, ensuring scalability and network isolation. 
- TPOT: I implemented a multi-honeypot environment using TPOT (Docker-based) to simulate a variety of attack vectors, including SSH (Cowrie), malware capture (Dionaea), and web application exploits (Glastopf).
- ELK Stack (Elasticsearch, Logstash, Kibana): I utilized the ELK stack to collect, store, and visualize attack data from honeypots in real-time.
- Firewall: I configured Vultr firewalls to restrict access and ensure proper isolation of honeypots.
- Docker: I utilized Docker to containerize the honeypots.
- Ubuntu Linux: I used Ubuntu Linux as the base operating system for the honeypots. Its compatibility with Docker and TPOT made it ideal for setting up and managing multiple honeypots in the cloud environment.
- PowerShell: I leveraged PowerShell to manage SSH connections and automate tasks across the honeypot environment. I securely accessed and configured the honeypot and ran the necessary scripts.

## Steps
### Provisioned the VPS: 
I deployed a new Virtual Private Server (VPS) on Vultr, selecting Ubuntu 22.04 x64 with 8GB+ RAM and 160GB of storage, meeting the resource requirements for T-Pot. Also, set up the firewall to make sure I only had access to the VPS at this point.

See below: VPS computing type and location.
![image](https://github.com/user-attachments/assets/91c40bd5-f210-4a66-93b5-d5b0ccffdc66)


See below: VPS specs. 

![image](https://github.com/user-attachments/assets/4da7bac9-225c-4aa7-bf4a-bd58d904ca67)


See below: Firewall configuration. 
![image](https://github.com/user-attachments/assets/481ee315-9553-4c26-bd9d-a3575cb6a9cc)




### Accessed the Server: 
I connected to the server via SSH using PowerShell, authenticating with the VPS IP address and root credentials.

See below: SSH connection.

![image](https://github.com/user-attachments/assets/de3bc9ab-d6f0-43fd-969c-43f1f415e069)



### Installed Dependencies: 
I updated the system’s packages and installed the necessary dependencies using the command apt-get update && apt-get upgrade to prepare the server for the installation.

See below: Installing dependencies. 

![image](https://github.com/user-attachments/assets/18695931-87cf-4b4f-9311-e82485121e21)




### Cloned T-Pot Repository: 
I cloned the T-Pot repository from GitHub to begin setting up the honeypot platform.

In this case I ran the following commands: 

git clone https://github.com/telekom-security/tpotce.git

cd tpotce


### Ran the T-Pot Installer: 
I executed the T-Pot installation script (env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
), following the prompts to configure the honeypot services and deploy the system. But I was given an error that it cannot be installed with the root user. I then created a user from my initials (jkzh), gave permissions, and switched user. Once doing so, I was able to install T-pot successfully. 

See below: Failed attempt at installation. 

![image](https://github.com/user-attachments/assets/a9b4e827-00d4-4941-b617-725713403b7a)



See below: Creation of the new user account.

![image](https://github.com/user-attachments/assets/8f990f81-420a-40a2-a8da-0cd1417d8baf)



See below: User switch.

![image](https://github.com/user-attachments/assets/1d285d65-51ba-436f-9e70-c8623f2c5aa2)



See below: Successful installation attempt. 

![image](https://github.com/user-attachments/assets/cb6e5f1e-85dd-4f4a-b1b4-8b5e5c125039)





### Configured Honeypot Services: 
I selected and configured the honeypot services I wanted to deploy, including options like Cowrie, Dionaea, and others, to simulate various attack surfaces.

### Verified the Setup: 
After installation, I checked the status of the containers (docker ps command) to ensure that T-Pot was running correctly and accessed the web interface for monitoring. I was then able to access t-pot using https and 108.61.142.108:64297 in my browser.

### Monitored & Analyzed Attacks: 
Using the T-Pot dashboard and logs, I monitored incoming attacks, analyzed attack patterns, and collected data to assess the effectiveness of the honeypot and its security capabilities.

### Blocked Malicious IP Address
After identifying suspicious activity from this IP, I configured the Vultr firewall settings to block the offending IP address, effectively preventing further interactions from the source without altering the honeypot's internal configuration. This helped mitigate potential risks and isolate unwanted traffic.

## Monitoring & Analyzing: 
I first opened the attack map and saw tons of activity immediately. I left the firewall settings for the Honeypot relaxed and open for a few hours to generate more traffic. When I returned, I noticed Australia had generated the most activity from the source IP of 170.64.163.118.



See below: Attack map. 
![image](https://github.com/user-attachments/assets/88bfc8d3-4335-4809-a2f1-24a741321000)



I then opened up Kibana by Elastic to analyze and get a better visual representation of everything. Immediately, I was presented with several dashboards with different honeypots. For this, I went ahead and picked the honeytrap dashboard. After clicking on the Honeytrap dashboard, I was presented with a great overview and more details on the traffic. I was able to see another view of the attack map. I saw how many unique source IP addresses and the number of attacks they generated. I also saw the known attackers and a pie chart breakdown of the known attackers vs. bots or a mass scanner. 

See below: List of honeypot dashboards. 
![image](https://github.com/user-attachments/assets/c6d5ff04-f3e5-484c-af17-2dd0413a41ee)


See below: Honeytrap dashboard. 
![image](https://github.com/user-attachments/assets/1e71edd7-3f53-4d06-99d3-80f804814080)




See below: Source IP reputation breakdown.
![image](https://github.com/user-attachments/assets/41a85a6b-0622-4eb7-90c4-1bdc66b6e756)



After that, I wanted to look more into that traffic from Australia as I remembered it had the most activity shown when reviewing the first attack map.
So, I went to the discover tab under analytics and set a filter to see activity from the source IP.
I filtered the data using the search filter src_ip: 170.64.163.118 in Elastic’s KQL query syntax. 
After doing this, I noticed the most recent log from that IP address was timestamped at 8:50 AM
I expanded the first event that I saw to get more information.  On the document's first page, I gathered general information like the destination IP, which led back to the Honeypot’s IP address: 108.61.142.108. I could also see the destination port, port 22, which is the port associated with SSH. On the second page, I was able to see more geographical data. I saw the general location of the honeypot, which was based out of New Jersey. I also saw the attacker's general location, which was showing as Sydney, Australia. On the third page of the expanded document, I was able to confirm both the IP address and the geographical time zone, which was listed as Australia/Sydney. I was also able to see that this was generated by one of the many known attackers.  

See below: Discover tab. 

![image](https://github.com/user-attachments/assets/5e224f0e-447d-4e9f-a762-45ce8cd88804)



See below: Location of honeypot server.

![image](https://github.com/user-attachments/assets/d2e2dd10-f1de-45df-9e2a-2fff6a9a3c30)


See below: Source IP filtered search results. 
![image](https://github.com/user-attachments/assets/26d566ee-8d87-4ef8-b9f9-ed1472abbff8)


See below: The first page of the document.
![image](https://github.com/user-attachments/assets/ae35c9da-b23e-468e-90a2-9148ce64a580)


See below: The second page of the document.
![image](https://github.com/user-attachments/assets/d9742136-01dd-4350-8126-3bf2ec3d66ae)


See below: The third page of the document.
![image](https://github.com/user-attachments/assets/b3f7a21c-e5ea-4121-9784-adbbc5a6dac3)




Though, at this time, I knew this was considered a known attacker in Kibana, I wanted to dig a bit more into this.

I used a popular OSINT tool called VirusTotal and did a search for the IP address. 
I saw 8 out of 94 security vendors flagged this IP address as malicious, including reputable security vendors like Cyble, Fortinet, and CDFR. I also used the tool AbuseIPDB to confirm. 
There, I saw over 300 reports of this IP address being malicious, with 100% confidence in the IP being abusive.  

See below: VirusTotal.
![image](https://github.com/user-attachments/assets/6fadce39-7018-4ef0-af37-e642486d362f)



See below: AbuseIPDB.
![image](https://github.com/user-attachments/assets/00d52128-489d-4c25-b112-cf2344ae601d)



This gave me enough information to be confident I should block this IP address in my Honeypot’s firewall setting.

### After completion of this project, this virtual private server has been decommissioned. 

# Thank you
I appreciate you taking the time out of your day to review my EZ-Honeypot project. 


