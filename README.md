### Note: The compiled .exe is unsigned. When you run it, Windows will show a SmartScreen warning. Please click "More info" -> "Run anyway" to proceed. For full transparency, you can always review and run the provided source code.
---

# **Spectre Documentation**

## 1. General Overview

**Spectre** is a utility for monitoring and managing system processes, services, startup items, and scheduled tasks in the Windows operating system. The program provides a **graphical interface** for analyzing system activity, detecting potentially suspicious elements, and taking action against them.

A key feature is integration with the **VirusTotal** service for in-depth file analysis, as well as a **rollback feature** for safely undoing changes made.

---

## 2. Key Features

* **Real-time Monitoring**: Displays lists of active processes, system services, startup programs, and scheduled tasks.

* **Threat Analysis**: Each element is assigned a danger score based on a set of heuristic rules (e.g., file location, privilege level).

* **Color Coding**: Elements are visually highlighted by color depending on their suspicion level for quick identification:

  * 🟥 **Red (Score 7+)**: High danger level.
  * 🟧 **Orange (Score 4-6)**: Medium suspicion level.
  * 🟨 **Yellow (Score 1-3)**: Low suspicion level.

* **VirusTotal Integration**: Ability to submit any executable file for analysis to **VirusTotal** directly from the interface and receive a detailed report.

### **Element Management**:

* **Processes**: Terminate selected processes.

* **Services**: Stop selected services.

* **Startup**: Remove registry entries.

* **Tasks**: Disable scheduled tasks.

* **Safe Rollback of Changes**: All actions (except terminating processes) are logged in a hidden `.changelog.json` file. Pressing **"Rollback Changes"** undoes all recorded actions in reverse order.

* **Flexible Selection**: Buttons for quickly selecting **non-system** or **suspicious** elements.

* **Detailed Information**: Double-click on any element to open a window with all collected information about it.

---

## 3. System Requirements and Installation

### 3.1 Requirements

* **Operating System**: Windows (for full functionality).
* **Python**: Version 3.x.

### 3.2 Required Libraries

* `customtkinter` — for creating the graphical interface.
* `psutil` — for gathering information about system processes and services.
* `pywin32` — for interacting with the Windows API (working with the registry, privileges, files).
* `requests` — for sending files to VirusTotal.

### 3.3 Installing Dependencies

Open the command prompt (cmd) or PowerShell and execute the following command:

```bash
pip install customtkinter psutil pywin32 requests
```

---

## 4. How to Use the Program

### 4.1 Launch

1. Save the code to a file named **Spectre.py**.
2. Run it from the command prompt:

   ```bash
   python Spectre.py
   ```

**Recommendation**: For full access to all system resources, **run the program as an administrator** (right-click on the cmd or `.py` file → "Run as Administrator").

If you run the program without administrator privileges for the first time, a warning window will appear, which will disappear after 5 seconds. The program will continue running in limited functionality mode.

### 4.2 Interface

The main window is divided into tabs:

* **Processes**: List of all active processes (except the Spectre program itself).
* **Services**: List of Windows system services.
* **Autostart**: Programs that run with the system (from the HKCU and HKLM registries).
* **Tasks**: Tasks scheduled in the Windows Task Scheduler.
* **Settings**: Program settings.

### 4.3 Settings (Settings Tab)

* **VirusTotal API Key**: This is the main setting. To enable scanning functionality, you need to:

  1. Click **"Get VirusTotal API Key."** A registration page will open on the VirusTotal website.
  2. Register or log in to your account.
  3. In your profile settings, find and copy your API key.
  4. Paste the key into the corresponding field in the program and click **"Save Settings."** The key will be saved in a hidden `.settings.json` file.

* **Open changelog**: Opens the `.changelog.json` file to view recorded actions.

### 4.4 Analysis Process and Actions

* **Update**: Click **"Refresh All"** to update lists in all tabs.
* **Analysis**: Review the lists and pay attention to elements highlighted in **red** and **orange**.
* **Detailed Information**: Double-click on any element to view all collected information about it (file path, user, integrity level, etc.).

#### VirusTotal Scan:

1. Select a process from the "Processes" tab.
2. Click the **"Scan Selected with VirusTotal"** button on the bottom panel.
3. Or, in the detailed information window for any element (if a file path is found), click the **"Scan with VirusTotal API"** button.
4. A waiting window will appear. After the scan is complete, a window with the full **JSON report** from VirusTotal will open.

#### Element Selection:

* **Select Non-System**: Selects all elements that do not belong to system users (e.g., System, Local Service).
* **Select Suspicious**: Opens a menu to select elements by danger level (Score 7+, 4-6, 1-3).
* **Clear Selection**: Deselects all selected elements.

#### Action Execution:

1. Select one or more elements.
2. Press the central action button (its name changes depending on the tab: "Terminate Selected," "Stop Selected," etc.).
3. Confirm the action in the dialog window.

#### Rollback Changes:

If you accidentally stopped the wrong service or deleted a required startup entry, click **"Rollback Changes."**

The program will read the change log and try to revert everything to its previous state (start the service, restore the registry entry, enable the task).

After a successful rollback, the change log is cleared.

---

## 5. Files Created by the Program

The program creates several files in its directory:

* **`.settings.json`** (hidden): Stores settings, including your VirusTotal API key.
* **`.changelog.json`** (hidden): Logs all changes made by the program, used for the rollback feature.
* **`crash.log`** (and `crash(1).log...`): Automatically created if the program encounters a critical error. Contains technical information useful for the developer.

---

License

This project is licensed under the MIT License - see the LICENSE file for details.
