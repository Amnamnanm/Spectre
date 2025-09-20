import customtkinter as ctk
from tkinter import ttk, messagebox, Menu, BooleanVar
import psutil
import os
import sys
import ctypes
import re
import shlex
import shutil
import json
import time
import datetime
import traceback
import webbrowser
import threading

if os.name == 'nt':
    import winreg
    import subprocess
    import xml.etree.ElementTree as ET
    try:
        import win32security
        import win32api
        import win32con
        import win32process
        import pywintypes
    except ImportError:
        messagebox.showerror("Dependency Missing", "The 'pywin32' library is required.\nPlease run: pip install pywin32")
        sys.exit(1)

try:
    import requests
except Exception:
    requests = None

def exception_logger(exc_type, exc_value, exc_traceback):
    try:
        base = "crash.log"; filename = base; counter = 1
        while os.path.exists(filename): filename = f"crash({counter}).log"; counter += 1
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Timestamp: " + datetime.datetime.utcnow().isoformat() + "Z\n\n")
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
    except Exception: pass
sys.excepthook = exception_logger

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0 if os.name == 'nt' else os.geteuid() == 0
    except Exception: return False

FILE_ATTRIBUTE_HIDDEN = 0x02; FILE_ATTRIBUTE_NORMAL = 0x80
def hide_file(filepath):
    if os.name == 'nt':
        try: ctypes.windll.kernel32.SetFileAttributesW(filepath, FILE_ATTRIBUTE_HIDDEN)
        except Exception: pass
def unhide_file(filepath):
    if os.name == 'nt':
        try: ctypes.windll.kernel32.SetFileAttributesW(filepath, FILE_ATTRIBUTE_NORMAL)
        except Exception: pass

SYSTEM_USERS = {'nt': ['system', 'система', 'local service', 'network service', 'trustedinstaller'], 'posix': ['root']}.get(os.name, [])

if os.name == 'nt':
    HIVE_MAP = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    ADMIN_GROUP_SID = "S-1-5-32-544"

CHANGELOG_FILE = ".changelog.json"; SETTINGS_FILE = ".settings.json"
def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: pass
    return {}
def save_settings(data):
    try:
        if os.path.exists(SETTINGS_FILE): unhide_file(SETTINGS_FILE)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        hide_file(SETTINGS_FILE)
    except Exception as e: messagebox.showerror("Error", f"Could not save settings: {e}")
def append_changelog(entry):
    try:
        changelog = []
        if os.path.exists(CHANGELOG_FILE):
            unhide_file(CHANGELOG_FILE)
            try:
                with open(CHANGELOG_FILE, "r", encoding="utf-8") as f: changelog = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError): changelog = []
        changelog.append(entry)
        with open(CHANGELOG_FILE, "w", encoding="utf-8") as f: json.dump(changelog, f, indent=2)
        hide_file(CHANGELOG_FILE)
    except Exception as e: messagebox.showerror("Error", f"Could not write changelog: {e}")
def clear_changelog():
    try:
        if os.path.exists(CHANGELOG_FILE):
            unhide_file(CHANGELOG_FILE); os.remove(CHANGELOG_FILE)
    except Exception: pass
def get_file_owner_type(path):
    if not path or not os.path.exists(path) or os.name != 'nt': return 'N/A'
    try:
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, _, _ = win32security.LookupAccountSid(None, owner_sid)
        if name.upper() in ('ADMINISTRATORS', 'SYSTEM', 'TRUSTEDINSTALLER'): return 'Admin/System'
        return 'User'
    except Exception: return 'Access Denied'
def sid_to_integrity_level(sid):
    try:
        s = win32security.ConvertSidToStringSid(sid); parts = s.split('-'); rid = int(parts[-1])
        if rid >= 16384: return "System"
        if rid >= 12288: return "High"
        if rid >= 8192: return "Medium"
        if rid >= 4096: return "Low"
        return f"Unknown({rid})"
    except Exception: return "Unknown"

def get_process_token_info(pid):
    info = {"integrity_level": "N/A", "privileges": [], "is_admin": False, "token_access_error": False}
    if os.name != 'nt': return info

    hProcess = None
    hToken = None
    try:
        PROCESS_QUERY = win32con.PROCESS_QUERY_LIMITED_INFORMATION
        hProcess = win32api.OpenProcess(PROCESS_QUERY, False, int(pid))
        hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_QUERY)

        try:
            tid = win32security.GetTokenInformation(hToken, win32security.TokenIntegrityLevel)
            info["integrity_level"] = sid_to_integrity_level(tid[0])
        except Exception: info["integrity_level"] = "Unknown"

        try:
            privs = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)
            info["privileges"] = [win32security.LookupPrivilegeName(None, p[0]) for p in privs]
        except Exception: info["privileges"] = []

        try:
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            info["is_admin"] = win32security.CheckTokenMembership(hToken, admin_sid)
        except Exception: info["is_admin"] = False

    except Exception as e:
        if hasattr(e, 'winerror') and e.winerror == 5:
            info["integrity_level"] = "Access Denied"
        info["token_access_error"] = True
    finally:
        if hToken: win32api.CloseHandle(hToken)
        if hProcess: win32api.CloseHandle(hProcess)

    return info

def is_system_item(owner_type, running_user=None):
    if running_user:
        normalized_user = running_user.split('\\')[-1].lower() if '\\' in running_user else running_user.lower()
        if normalized_user in SYSTEM_USERS:
            return True
        else:
            return False
    if owner_type == 'Admin/System':
        return True
    return False

def extract_executable_path(command_string):
    if not command_string: return ""
    try:
        expanded = os.path.expandvars(command_string); parts = shlex.split(expanded)
        if not parts: return ""
        executable = parts[0]
        if os.path.isfile(executable): return executable
        else: return shutil.which(executable) or ""
    except Exception: return ""
def determine_task_permission_level(run_as_user, highest_privileges, group_id=None, path=None):
    if run_as_user and run_as_user.lower() in SYSTEM_USERS: return "System"
    if highest_privileges: return "Administrator"
    if group_id and group_id == ADMIN_GROUP_SID: return "Administrator"
    if path and get_file_owner_type(path) == 'Admin/System': return "Administrator (file owner)"
    return "User"

class SystemManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.data_caches = {'Processes': {}, 'Services': {}, 'Autostart': {}, 'Tasks': {}}
        self.current_pid = os.getpid()
        self.suspicion_non_system_only = BooleanVar(value=True)
        self.suspicion_menu = None
        self.setup_gui()
        self.refresh_all()

    def setup_gui(self):
        ctk.set_appearance_mode("Dark"); self.title("Spectre"); self.geometry("1600x900")
        top_frame = ctk.CTkFrame(self); top_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkButton(top_frame, text="Refresh All", command=self.refresh_all).pack(side="right", padx=10)
        ctk.CTkButton(top_frame, text="Rollback Changes", command=self.rollback_changes).pack(side="right", padx=10)
        self.notebook = ctk.CTkTabview(self, command=self.on_tab_change); self.notebook.pack(padx=10, pady=(0, 10), expand=True, fill="both")
        self.tabs = {name: self.notebook.add(name) for name in list(self.data_caches.keys()) + ['Settings']}
        self.trees = {
            'Processes': self.create_treeview(self.tabs['Processes'], ('Score', 'PID', 'Name', 'User', 'Permissions', 'Analysis')),
            'Services': self.create_treeview(self.tabs['Services'], ('Score', 'Name', 'Status', 'Start Type', 'Permissions', 'Analysis')),
            'Autostart': self.create_treeview(self.tabs['Autostart'], ('Score', 'Name', 'Source', 'Permissions', 'Analysis')),
            'Tasks': self.create_treeview(self.tabs['Tasks'], ('Score', 'Name', 'Run As User', 'Permissions', 'Analysis'))}
        for tree in self.trees.values(): tree.bind("<Double-1>", self.show_detailed_info)
        self.setup_settings_tab()
        button_frame = ctk.CTkFrame(self); button_frame.pack(pady=(0, 10), padx=10, fill="x")
        button_frame.columnconfigure((0, 1, 2, 3, 4), weight=1)
        ctk.CTkButton(button_frame, text="Select Non-System", command=self.select_non_system).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.suspicious_btn = ctk.CTkButton(button_frame, text="Select Suspicious", command=self.toggle_suspicion_menu)
        self.suspicious_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.scan_button = ctk.CTkButton(button_frame, text="Scan Selected with VirusTotal", command=self.scan_selected_process)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        self.action_button = ctk.CTkButton(button_frame, text="Action", command=self.perform_action)
        self.action_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(button_frame, text="Clear Selection", command=self.clear_selection).grid(row=0, column=4, padx=5, pady=5, sticky="ew")
        self.on_tab_change()

    def setup_settings_tab(self):
        tab = self.tabs['Settings']; frame = ctk.CTkFrame(tab); frame.pack(padx=20, pady=20, fill="both", expand=True)
        ctk.CTkLabel(frame, text="VirusTotal API Key:").pack(anchor='w', pady=(0,6))
        self.vt_key_entry = ctk.CTkEntry(frame, width=600); self.vt_key_entry.pack(anchor='w'); self.vt_key_entry.insert(0, self.settings.get('virustotal_api_key', ''))
        btn_frame = ctk.CTkFrame(frame); btn_frame.pack(anchor='w', pady=10)
        ctk.CTkButton(btn_frame, text="Save Settings", command=self.save_settings_ui).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="Get VirusTotal API Key", command=self.open_virustotal_signup).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="Open changelog", command=self.open_changelog).pack(side="left", padx=4)

    def vt_scan_and_show(self, path):
        api_key = self.settings.get('virustotal_api_key', '') or self.vt_key_entry.get().strip()
        if not api_key:
            messagebox.showwarning("No API Key", "VirusTotal API key is not configured in Settings."); return
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", f"File not found for scanning:\n{path}"); return

        wait_window = ctk.CTkToplevel(self)
        wait_window.title("Scanning...")
        wait_window.geometry("300x100")
        wait_window.transient(self)
        wait_window.grab_set()
        ctk.CTkLabel(wait_window, text=f"Uploading and scanning:\n{os.path.basename(path)}\nPlease wait...", justify="center").pack(expand=True)
        wait_window.update()

        scan_thread = threading.Thread(
            target=self._perform_vt_scan_threaded,
            args=(path, api_key, wait_window)
        )
        scan_thread.daemon = True
        scan_thread.start()

    def _perform_vt_scan_threaded(self, path, api_key, wait_window):
        if not requests:
            self.after(0, self._show_vt_result, {"error": "requests library not available"}, wait_window)
            return

        headers = {"x-apikey": api_key}
        analysis_id = None
        final_result = None

        try:
            with open(path, "rb") as f:
                files = {"file": (os.path.basename(path), f)}
                res = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=60)

            if res.status_code == 200:
                analysis_id = res.json().get("data", {}).get("id")
            else:
                final_result = {"error": f"VT upload error: {res.status_code}", "raw": res.text}
        except Exception as e:
            final_result = {"error": str(e)}

        if analysis_id:
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(12):
                try:
                    res = requests.get(analysis_url, headers=headers, timeout=20)
                    if res.status_code == 200:
                        data = res.json()
                        status = data.get("data", {}).get("attributes", {}).get("status")
                        if status == "completed":
                            final_result = data
                            break
                        time.sleep(10)
                    else:
                        final_result = {"error": f"VT analysis fetch error: {res.status_code}", "raw": res.text}
                        break
                except Exception as e:
                    final_result = {"error": str(e)}
                    break
            else:
                final_result = {"error": "Scan timed out. The report was not ready in time."}

        self.after(0, self._show_vt_result, final_result, wait_window)

    def _show_vt_result(self, result_data, wait_window):
        wait_window.destroy()

        if result_data is None:
            messagebox.showerror("Error", "Failed to get a valid response from VirusTotal.")
            return

        win = ctk.CTkToplevel(self)
        win.title("VirusTotal Report")
        win.geometry("700x500")
        textbox = ctk.CTkTextbox(win, wrap="word", font=("Courier New", 11))
        textbox.pack(expand=True, fill="both", padx=10, pady=10)
        textbox.insert("0.0", json.dumps(result_data, indent=2, ensure_ascii=False))
        textbox.configure(state="disabled")

    def scan_selected_process(self):
        active_tab = self.notebook.get()
        if active_tab != 'Processes': return
        tree = self.trees.get(active_tab)
        if not tree or not tree.selection(): messagebox.showinfo("No Selection", "Please select a process to scan."); return
        item_id = tree.selection()[0]
        try: pid = int(item_id)
        except (ValueError, TypeError): return
        data = self.data_caches[active_tab].get(pid)
        if not data: return
        path = data.get('path')
        if path:
            self.vt_scan_and_show(path)
        else:
            messagebox.showinfo("No File", f"The selected process '{data.get('name')}' does not have an accessible executable file path.")

    def open_virustotal_signup(self):
        try: webbrowser.open_new("https://www.virustotal.com/gui/join-us")
        except Exception as e: messagebox.showerror("Error", f"Could not open browser: {e}")
    def save_settings_ui(self):
        key = self.vt_key_entry.get().strip(); self.settings['virustotal_api_key'] = key
        save_settings(self.settings); messagebox.showinfo("Saved", "Settings saved successfully.")
    def open_changelog(self):
        if not os.path.exists(CHANGELOG_FILE): messagebox.showinfo("Changelog", "No changelog found."); return
        try:
            with open(CHANGELOG_FILE, "r", encoding="utf-8") as f: data = json.load(f)
            win = ctk.CTkToplevel(self); win.title("Changelog"); win.geometry("700x500")
            textbox = ctk.CTkTextbox(win, wrap="word", font=("Courier New", 11)); textbox.pack(expand=True, fill="both", padx=10, pady=10)
            textbox.insert("0.0", json.dumps(data, indent=2)); textbox.configure(state="disabled")
        except Exception as e: messagebox.showerror("Error", f"Could not open changelog: {e}")
    def create_treeview(self, parent, columns):
        tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns: tree.heading(col, text=col); tree.column(col, width=150, anchor='w')
        tree.column('Score', width=60, anchor='center')
        if 'PID' in columns: tree.column('PID', width=60, anchor='center')
        scrollbar = ctk.CTkScrollbar(parent, command=tree.yview); tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y"); tree.pack(expand=True, fill="both")
        return tree
    def get_processes(self):
        cache = self.data_caches['Processes']; cache.clear()
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            if proc.info['pid'] == self.current_pid: continue
            try:
                p_info = proc.info; p_info['path'] = p_info.get('exe'); p_info['file_owner'] = get_file_owner_type(p_info['path'])
                token_info = get_process_token_info(p_info['pid'])
                if token_info['token_access_error']:
                    p_info['permissions'] = "Access Denied to Token"
                else:
                    p_info['permissions'] = f"IL: {token_info.get('integrity_level','N/A')}; Admin: {token_info.get('is_admin',False)}"
                p_info['is_system'] = is_system_item(p_info['file_owner'], running_user=p_info.get('username'))
                p_info['score'], p_info['reason'] = self.analyze_threat('process', p_info)
                cache[p_info['pid']] = p_info
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass

    def get_services(self):
        cache = self.data_caches['Services']; cache.clear()
        if os.name != 'nt': return
        for service in psutil.win_service_iter():
            try:
                s_info = service.as_dict()
                binpath = s_info.get('binpath', '')
                s_info['path'] = extract_executable_path(binpath)
                s_info['file_owner'] = 'N/A'

                if not s_info['path']:
                    if 'svchost.exe' in binpath.lower():
                        permission_str = "Hosted Service (svchost)"
                    elif '.sys' in binpath.lower():
                        permission_str = "Kernel Driver"
                    elif not binpath:
                        permission_str = "Path not specified"
                    else:
                        permission_str = "Path not resolved"
                else:
                    file_owner = get_file_owner_type(s_info['path'])
                    s_info['file_owner'] = file_owner
                    permission_str = f"Owner: {file_owner}"

                s_info['permissions'] = permission_str
                s_info['is_system'] = is_system_item(s_info.get('file_owner'), running_user=s_info.get('username'))
                s_info['score'], s_info['reason'] = self.analyze_threat('service', s_info)
                cache[s_info['name']] = s_info
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
                s_name = "Unknown"
                try: s_name = service.name()
                except Exception: pass
                cache[s_name] = {'name': s_name, 'status': 'ACCESS_DENIED', 'score': 1, 'reason': f'Error reading service: {e}'}

    def get_autostarts(self):
        cache = self.data_caches['Autostart']; cache.clear()
        if os.name != 'nt': return
        def read_registry(hive_int, hive_str, path, source):
            try:
                with winreg.OpenKey(hive_int, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try: name, command, _ = winreg.EnumValue(key, i)
                        except OSError: continue
                        exec_path = extract_executable_path(command); file_owner = get_file_owner_type(exec_path)
                        is_system = is_system_item(file_owner) or hive_str == "HKLM"
                        entry = {'name': name, 'command': command, 'path': exec_path, 'source': source, 'permissions': f"Owner:{file_owner}", 'file_owner': file_owner, 'is_system': is_system}
                        entry['score'], entry['reason'] = self.analyze_threat('autostart', entry); cache[f"reg_{hive_str}_{name}"] = entry
            except FileNotFoundError: pass
        read_registry(winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run")
        read_registry(winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run")
    def get_tasks(self):
        cache = self.data_caches['Tasks']; cache.clear()
        if os.name != 'nt': return
        try:
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(['schtasks', '/query', '/xml', 'ONE'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, startupinfo=startupinfo)
            xml_output, _ = proc.communicate()
            if not xml_output: return
            root = ET.fromstring(xml_output); ns = {'ns': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
            for task_node in root.findall('.//ns:Task', ns):
                try:
                    name_node = task_node.find('ns:RegistrationInfo/ns:URI', ns)
                    if name_node is None: continue
                    name = name_node.text.lstrip('\\')

                    principal = task_node.find('ns:Principals/ns:Principal', ns)
                    run_as_user = principal.find('ns:UserId', ns).text if principal is not None and principal.find('ns:UserId', ns) is not None else None
                    group_id = principal.find('ns:GroupId', ns).text if principal is not None and principal.find('ns:GroupId', ns) is not None else None
                    runlevel = principal.find('ns:RunLevel', ns).text if principal is not None and principal.find('ns:RunLevel', ns) is not None else None
                    highest_privileges = runlevel == 'HighestAvailable'

                    action_node = task_node.find('.//ns:Command', ns)
                    command = action_node.text if action_node is not None else ''

                    path = extract_executable_path(command)
                    file_owner = get_file_owner_type(path)
                    entry = {
                        'name': name,
                        'run_as_user': run_as_user or 'N/A',
                        'action': command,
                        'path': path,
                        'file_owner': file_owner,
                        'permissions': determine_task_permission_level(run_as_user, highest_privileges, group_id, path=path),
                        'is_system': is_system_item(file_owner, running_user=run_as_user)
                    }
                    entry['score'], entry['reason'] = self.analyze_threat('task', entry)
                    cache[name] = entry
                except (AttributeError, ET.ParseError):
                    if 'name' in locals(): cache[name] = {'name': name, 'score': 1, 'reason': 'Malformed task data'}
        except Exception as e: cache['error'] = {'name': 'Could not run schtasks.exe', 'score': 0, 'reason': f'Error: {e}'}
    def analyze_threat(self, item_type, data):
        score = 0; reason = []
        path = data.get('path', '') or data.get('command', '') or ''; name = data.get('name', '')
        if re.search(r'\\temp\\|\\appdata\\|\\downloads\\', (path + name).lower()): score += 3; reason.append("Runs from user/temp path")
        perms = data.get('permissions','');
        if 'High' in str(perms) or 'System' in str(perms) or 'Administrator' in str(perms): score += 2; reason.append("High privileges")
        if not path: score += 2; reason.append("No executable path")
        if data.get('file_owner') == 'Access Denied' or str(data.get('permissions','')).startswith('Access Denied'): score += 2; reason.append("Access Denied reading file")
        return score, "; ".join(reason)
    def populate_all_trees(self):
        self.populate_tree('Processes', lambda p: (p['score'], p['pid'], p['name'], p.get('username', 'N/A'), p['permissions'], p['reason']))
        self.populate_tree('Services', lambda s: (s['score'], s.get('name', 'N/A'), s.get('status', 'N/A'), s.get('start_type', 'N/A'), s.get('permissions', 'N/A'), s.get('reason', 'N/A')))
        self.populate_tree('Autostart', lambda a: (a['score'], a['name'], a['source'], a['permissions'], a['reason']))
        self.populate_tree('Tasks', lambda t: (t['score'], t['name'], t.get('run_as_user', 'N/A'), t.get('permissions', 'N/A'), t.get('reason', 'N/A')))
    def populate_tree(self, name, value_func):
        tree = self.trees[name]; cache = self.data_caches[name]; tree.delete(*tree.get_children())
        sorted_keys = sorted(cache.keys(), key=lambda k: cache[k].get('score', 0), reverse=True)
        for key in sorted_keys:
            item = cache[key]; values = value_func(item); tags = ()
            score = item.get('score', 0)
            if score >= 7: tags = ('critical',)
            elif score >= 4: tags = ('warning',)
            elif score > 0: tags = ('suspicious',)
            tree.insert("", "end", iid=key, values=values, tags=tags)
        tree.tag_configure('critical', background='#8B0000'); tree.tag_configure('warning', background='#FF8C00'); tree.tag_configure('suspicious', background='#F0E68C')
    def refresh_all(self):
        try: self.get_processes(); self.get_services(); self.get_autostarts(); self.get_tasks(); self.populate_all_trees()
        except Exception as e: messagebox.showerror("Error", f"Error refreshing data: {e}")
    def on_tab_change(self, event=None):
        active_tab = self.notebook.get()
        actions = {'Processes': 'Terminate Selected', 'Services': 'Stop Selected', 'Autostart': 'Remove Selected', 'Tasks': 'Disable Selected'}
        self.action_button.configure(text=actions.get(active_tab, "Action"))
        if active_tab == 'Processes': self.scan_button.grid()
        else: self.scan_button.grid_remove()
    def show_detailed_info(self, event):
        active_tab = self.notebook.get(); tree = self.trees.get(active_tab)
        if not tree or not tree.selection(): return
        item_id = tree.selection()[0]
        if active_tab == 'Processes':
            try: item_id = int(item_id)
            except (ValueError, TypeError): return
        data = self.data_caches[active_tab].get(item_id)
        if not data: return
        win = ctk.CTkToplevel(self); win.title(f"Details for {data.get('name', item_id)}"); win.geometry("800x600")
        textbox = ctk.CTkTextbox(win, wrap="word", font=("Courier New", 11)); textbox.pack(expand=True, fill="both", padx=10, pady=10)
        info_str = "\n".join(f"{str(key):<20}: {str(value)}" for key, value in data.items())
        textbox.insert("0.0", info_str); textbox.configure(state="disabled")
        path = data.get('path') or ''
        btn_frame = ctk.CTkFrame(win); btn_frame.pack(fill="x", padx=10, pady=(0,10))
        if path: ctk.CTkButton(btn_frame, text="Scan with VirusTotal API", command=lambda p=path: self.vt_scan_and_show(p)).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Close", command=win.destroy).pack(side="right", padx=6)
    def select_non_system(self):
        active_tab = self.notebook.get(); tree = self.trees.get(active_tab); cache = self.data_caches.get(active_tab)
        if not tree or not cache: return
        self.clear_selection(); tree.selection_set([iid for iid, item in cache.items() if not item.get('is_system')])
    
    def check_menu_close(self, event):
        if self.suspicion_menu and self.suspicion_menu.winfo_exists():
            menu_x, menu_y = self.suspicion_menu.winfo_rootx(), self.suspicion_menu.winfo_rooty()
            menu_w, menu_h = self.suspicion_menu.winfo_width(), self.suspicion_menu.winfo_height()
            if not (menu_x <= event.x_root <= menu_x + menu_w and menu_y <= event.y_root <= menu_y + menu_h):
                self.destroy_suspicion_menu()

    def destroy_suspicion_menu(self):
        if self.suspicion_menu and self.suspicion_menu.winfo_exists():
            self.unbind_all("<Button-1>")
            self.suspicion_menu.destroy()
            self.suspicion_menu = None

    def toggle_suspicion_menu(self):
        if self.suspicion_menu and self.suspicion_menu.winfo_exists():
            self.destroy_suspicion_menu()
            return

        self.suspicion_menu = ctk.CTkToplevel(self)
        self.suspicion_menu.overrideredirect(True)
        self.suspicion_menu.transient(self)

        menu_frame = ctk.CTkFrame(self.suspicion_menu, border_width=1, border_color="gray50")
        menu_frame.pack(expand=True, fill="both")
        
        ctk.CTkCheckBox(menu_frame, text="Non-system only", variable=self.suspicion_non_system_only, onvalue=True, offvalue=False).pack(pady=5, padx=10, anchor='w')
        ctk.CTkFrame(menu_frame, height=1, fg_color="gray40").pack(fill='x', padx=5)
        
        btn_style = {"anchor": "w", "fg_color": "transparent", "hover_color": "gray20"}
        ctk.CTkButton(menu_frame, text="Most Likely (Score 7+)", **btn_style, command=lambda: self.select_by_score_and_close(7, 99)).pack(fill='x', padx=5, pady=(5, 2))
        ctk.CTkButton(menu_frame, text="Probably (Score 4-6)", **btn_style, command=lambda: self.select_by_score_and_close(4, 6)).pack(fill='x', padx=5, pady=2)
        ctk.CTkButton(menu_frame, text="Potentially (Score 1-3)", **btn_style, command=lambda: self.select_by_score_and_close(1, 3)).pack(fill='x', padx=5, pady=(2, 5))

        self.suspicion_menu.update_idletasks()

        menu_height = self.suspicion_menu.winfo_height()
        x = self.suspicious_btn.winfo_rootx()
        y = self.suspicious_btn.winfo_rooty() - menu_height - 2

        self.suspicion_menu.geometry(f"+{x}+{y}")
        
        self.after(50, lambda: self.bind_all("<Button-1>", self.check_menu_close))

    def select_by_score_and_close(self, min_score, max_score):
        self.select_by_score(min_score, max_score)
        self.destroy_suspicion_menu()

    def select_by_score(self, min_score, max_score):
        active_tab = self.notebook.get(); tree = self.trees.get(active_tab); cache = self.data_caches.get(active_tab)
        if not tree or not cache: return
        self.clear_selection()
        non_system_only = self.suspicion_non_system_only.get()
        items_to_select = []
        for iid, item in cache.items():
            if not (min_score <= item.get('score', 0) <= max_score):
                continue
            if non_system_only and item.get('is_system', False):
                continue
            items_to_select.append(iid)
        tree.selection_set(items_to_select)
        if items_to_select and active_tab == 'Tasks': messagebox.showinfo("Manual Check Recommended", "Analysis complete. Please manually review the selected high-privilege tasks before disabling them.")

    def clear_selection(self):
        if tree := self.trees.get(self.notebook.get()): tree.selection_set([])
    def perform_action(self):
        active_tab = self.notebook.get(); tree = self.trees.get(active_tab); selected_items = tree.selection()
        if not selected_items: messagebox.showinfo("No Selection", "Please select one or more items."); return
        actions = {'Processes': ('TERMINATE', self.terminate_processes), 'Services': ('STOP', self.stop_services), 'Autostart': ('PERMANENTLY REMOVE', self.remove_autostarts), 'Tasks': ('DISABLE', self.disable_tasks)}
        action_name, action_func = actions.get(active_tab)
        if not messagebox.askyesno("Confirm Action", f"Are you sure you want to {action_name} {len(selected_items)} item(s)?"): return
        action_func(selected_items); self.refresh_all()
    def terminate_processes(self, pids):
        success, fail = 0, 0
        for pid in pids:
            try:
                if int(pid) == self.current_pid:
                    messagebox.showwarning("Action Blocked", "Cannot terminate the Spectre application itself.")
                    continue
                psutil.Process(int(pid)).terminate(); success += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied): fail += 1
        messagebox.showinfo("Result", f"Terminated: {success}\nFailed: {fail}")
    def stop_services(self, service_names):
        success, fail = 0, 0;
        if os.name != 'nt': messagebox.showinfo("Not Supported", "Service control supported on Windows only."); return
        for name in service_names:
            try:
                svc = psutil.win_service_get(name); prev_status = svc.status(); svc.stop(); success += 1
                append_changelog({"type": "service", "name": name, "action": "stopped", "timestamp": datetime.datetime.utcnow().isoformat() + "Z", "prev_status": prev_status})
            except Exception: fail += 1
        messagebox.showinfo("Result", f"Stopped: {success}\nFailed: {fail}")
    def remove_autostarts(self, item_ids):
        success, fail = 0, 0
        if os.name != 'nt': return
        for item_id in item_ids:
            try:
                _, hive_str, name = item_id.split('_', 2); hive = HIVE_MAP[hive_str]; key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                value = None
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key: value, _ = winreg.QueryValueEx(key, name)
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key: winreg.DeleteValue(key, name)
                success += 1; append_changelog({"type": "autostart", "name": name, "action": "removed", "hive": hive_str, "timestamp": datetime.datetime.utcnow().isoformat() + "Z", "value": value})
            except (ValueError, OSError, KeyError, FileNotFoundError): fail += 1
        messagebox.showinfo("Result", f"Removed: {success}\nFailed: {fail}")
    def disable_tasks(self, task_names):
        success, fail = 0, 0
        if os.name != 'nt': return
        for name in task_names:
            try:
                startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.check_call(['schtasks', '/change', '/tn', name, '/disable'], startupinfo=startupinfo, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                success += 1; append_changelog({"type": "task", "name": name, "action": "disabled", "timestamp": datetime.datetime.utcnow().isoformat() + "Z"})
            except subprocess.CalledProcessError: fail += 1
        messagebox.showinfo("Result", f"Disabled: {success}\nFailed: {fail}")
    def rollback_changes(self):
        if not os.path.exists(CHANGELOG_FILE): messagebox.showinfo("Rollback", "No changelog to rollback."); return
        try:
            with open(CHANGELOG_FILE, "r", encoding="utf-8") as f: changelog = json.load(f)
        except Exception as e: messagebox.showerror("Error", f"Could not read changelog: {e}"); return
        failures = []
        for entry in reversed(changelog):
            try:
                t = entry.get('type')
                if t == 'service' and entry.get('action') == 'stopped':
                    try: psutil.win_service_get(entry.get('name')).start()
                    except Exception: failures.append(entry)
                elif t == 'autostart' and entry.get('action') == 'removed':
                    hive = HIVE_MAP.get(entry.get('hive'))
                    if hive and entry.get('value'):
                        try:
                            with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                                winreg.SetValueEx(key, entry.get('name'), 0, winreg.REG_SZ, entry.get('value'))
                        except Exception: failures.append(entry)
                elif t == 'task' and entry.get('action') == 'disabled':
                    try:
                        startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        subprocess.check_call(['schtasks', '/change', '/tn', entry.get('name'), '/enable'], startupinfo=startupinfo, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                    except Exception: failures.append(entry)
            except Exception: failures.append(entry)
        if failures: messagebox.showwarning("Rollback Completed With Issues", f"Rollback finished but {len(failures)} items failed to restore.")
        else: messagebox.showinfo("Rollback Completed", "All logged changes rolled back successfully."); clear_changelog()
        self.refresh_all()

if __name__ == "__main__":
    if not is_admin(): messagebox.showwarning("Permissions", "Running without admin privileges may limit access to system processes and information.")
    app = SystemManagerApp()
    app.mainloop()