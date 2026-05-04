# GPO-hardening-2019
intern proj

# Windows Server 2019 CIS Hardening Tool

This project automates the **CIS Microsoft Windows Server 2019 Benchmark** (Level 1 & 2). 
It is designed to be modular, allowing for easy auditing and remediation without 
manual registry editing.

## 📂 File Structure
* **Main.ps1**: The interactive controller. **Run this first.**
* **Hardening-Functions.ps1**: Contains all remediation logic (Registry, Secedit, Services).
* **Audit-Functions.ps1**: Contains validation logic to check current compliance.

## 🚀 How to Use
1.  Copy the entire folder to the target server. Ensure that the file details match exactly to the original folder. Make sure ALL files are in the server.
2.  Open **PowerShell** as **Administrator**.
3.  Set the execution policy for the session:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process
    ```
4.  Launch the tool: (cd to the file directory)
    ```powershell
    .\main.ps1
    ```
5.  **Option 1 (Audit)**: Generates a CSV report of current gaps.
6.  **Option 2 (Hardening)**: Applies all CIS-recommended settings.

## 📊 Documentation
After running an Audit, a CSV file named `Audit_Report_YYYYMMDD.csv` will be 
generated in the root folder. This can be used as evidence for security 
compliance reviews.

## ⚠️ Requirements
* Windows Server 2019
* Administrator Privileges
* LAPS (Local Administrator Password Solution) installed (for LAPS functions)