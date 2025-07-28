
![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/8fcf8800a4a977166ff68d2114e108eda6ad9a3f/%F0%9F%8E%AFAzure_Honey-pot_Lab_with_Microsoft_Sentinel.png)

Setting up a realistic honeypot using a Windows VM on Microsoft Azure, monitoring brute-force RDP attacks, harvesting logs with geolocation data, and visualize attacker sources on a map — all through Microsoft Sentinel. Appended Incident reponse alerts to trigger when a attack was occuring using the logic app to connect to the logic analystics workspace.

> 🔗 Inspired by the Cyber Range and Josh Madakor’s labs.

---

## 📌 Contents

1. [Azure Subscription Setup](#1-azure-subscription-setup)  
2. [Create the Honeypot VM](#2-create-the-honeypot-vm)  
3. [Login Events and Security Logs](#3-login-events-and-security-logs)  
4. [Log Analytics and KQL](#4-log-analytics-and-kql)  
5. [Log Enrichment (GeoIP)](#5-log-enrichment-geoip)  
6. [Create a Real-Time Attack Map](#6-create-a-real-time-attack-map)

---

## 1. Azure Subscription Setup

- 👉 Create a **free Azure subscription**:  
  [https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)

- 🔁 If a free account is unavailable:
  - Use a paid account (be mindful of costs).
 

- 🖥️ Azure Portal login:  
  [https://portal.azure.com](https://portal.azure.com)

---

## 2. Create the Honeypot VM

1. In Azure Portal, search: **Virtual Machines** → Create a **Windows 10** VM.
2. Choose a suitable size (smaller is cheaper).
3. **Remember** your username & password.
4. Go to the **Network Security Group (NSG)**:
   - Add an **inbound rule**: Allow all traffic (use `*` ports).
5. RDP into the VM and turn off the firewall:
   - Run: `wf.msc` → Properties → Turn off Domain, Private, and Public firewalls.
  
![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/40c545842c06daa2cecc17107b2e13eb6cf8d7ca/virtual%20machine%2C%20firewall%2C%20and%20ip.png)

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/53485e2c61ee039c98f3d5e9e889125c4d793567/Inside%20vm%20and%20disabling%20firewall.png)

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/remote%20desktop%20protocol.png)

---

## 3. Login Events and Security Logs

1. On the honeypot VM, **simulate failed logins**:
   - Attempt to log in 3 times with a fake user (e.g. `employee`).
2. Open **Event Viewer** → Security Logs.
3. Look for:
   - **Event ID 4625** (failed login attempts)

---

## 4. Log Analytics and KQL

### Step-by-step:

- 🔧 Create a **Log Analytics Workspace (LAW)**
- ➕ Add **Microsoft Sentinel** to the workspace
- 🛠️ Use the **Windows Security Events via AMA** connector
- 📌 Set up a **Data Collection Rule (DCR)** to forward logs
- 🔍 Confirm logs from your honeypot are arriving in Sentinel

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/azure%20moniitorinf%20windows%20agent.png)

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/install%20microsoft%20sential%20and%20download%20windows%20security%20events.png)


### Sample KQL Query:
```
SecurityEvent
| where EventID == 4625

💡 Sentinel uses Kusto Query Language (KQL), similar to SQL. 
```
![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/logs%20being%20forwared%20to%20law%20workspace%20from%20monitoring%20agent.png)

## 5. Log Intergration (GeoIP)

By default, login logs show IP addresses but no location. We need to add them using a GeoIP watchlist.

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/using%20geo%20location%20to%20map%20attackers.png)

### 🔽 Step-by-step:

1. **Download the GeoIP CSV**:
https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view

2. **In Microsoft Sentinel → Watchlists**:
- **Name / Alias**: `geoip`
- **Source Type**: Local file
- **Search Key Column**: `network`
- **Header Rows to Skip**: `0`
- Upload the CSV file (about **54,000 rows**)

3. **KQL to enrich logs with GeoIP**:
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents

🌍 This query will integrate logs with geolocation info(from the geo-ip file) by matching attacker IP addresses against the watchlist to view where the attack came from.
```

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/using%20geo%20location%20to%20narrow%20down%20person%20with%20ip%20address.png)

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/4abbbc8848fbd0d94aad80109ad9dcc9b252ce0b/ip%20lookup%20of%20log.png)

## 6. Create a Real-Time Attack Map

These are the steps to create a geographic visualization of brute-force login attempts using Microsoft Sentinel:

### 🛠️ Steps:

1. Go to **Microsoft Sentinel → Workbooks → New Workbook**
2. **Delete** any default or preloaded elements
3. Click **"Add Query"** to insert a new query tile
4. Open the **Advanced Editor** tab
5. **Paste in the `map.json` configuration**  
   > 🗂️ Get the `map.json` file from [Josh’s GitHub Sentinel Lab](https://github.com/joshmadakor1/Sentinel-Lab)
6. Click **Save** and **Run** the workbook

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/49732e87b3afaadf7523b05e1e38685a4e9d3a6a/attack%20map%20creation.png)

✅ You’ll now see **real-time attack data** mapped by geographic location — giving you a clear, visual view of where brute-force login attempts are coming from around the world.

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/49732e87b3afaadf7523b05e1e38685a4e9d3a6a/updated%20attack%20map%20with%20more%20attacks.png)

---

## 7. Creating Automated Incident responses for the SOC using the Logic App

1. Go to **Logic app → Add resource group to SOC → Apply region**
2. **Add a trigger on the logic app** to add sentinal incident creation rule
3. Click **"Any sentinal rule"** then choose and operation
4. **Save rule triggers** then activate the rule
5. **Edit the automation rule** then add any conditions and apply the playbook(the logic app trigger we created) and activate the rule
6. **Now when viewing the incidents in sentinal** We can see every attack that comes through is logged through severity and when it occurs

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/49732e87b3afaadf7523b05e1e38685a4e9d3a6a/%23using%20logic%20app%20to%20create%20automated%20incident%20repsonses.png)

![](https://github.com/Sheynm1/Azure-Honeypot-Lab-with-Microsoft-Sentinel/blob/49732e87b3afaadf7523b05e1e38685a4e9d3a6a/automated%20responses.png)

## 📚 Resources

- 💻 [Azure Free Account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)
- 📦 [GeoIP Watchlist CSV](https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/misc/geoip-summarized.csv)
- 🛠️ [Josh’s GitHub Sentinel Lab](https://github.com/joshmadakor1/Sentinel-Lab)
