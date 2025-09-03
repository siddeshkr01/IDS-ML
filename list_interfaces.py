from scapy.all import get_if_list, get_if_hwaddr, conf
import winreg

def get_interface_description(iface):
    """Get the human-readable description of a network interface on Windows."""
    try:
        # Open the Windows registry key for network interfaces
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        reg_key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}")
        
        # Extract the GUID from the scapy interface name (e.g., \Device\NPF_{GUID})
        guid = iface.split("NPF_")[1] if "NPF_" in iface else iface
        
        # Open the subkey for this GUID
        subkey = winreg.OpenKey(reg_key, f"{guid}\\Connection")
        description, _ = winreg.QueryValueEx(subkey, "Name")
        winreg.CloseKey(subkey)
        winreg.CloseKey(reg_key)
        winreg.CloseKey(reg)
        return description
    except Exception as e:
        return f"Unknown ({str(e)})"

# List all interfaces with their descriptions
print("Available Network Interfaces:")
for iface in get_if_list():
    description = get_interface_description(iface)
    print(f"Interface: {iface}")
    print(f"Description: {description}")
    print("---")