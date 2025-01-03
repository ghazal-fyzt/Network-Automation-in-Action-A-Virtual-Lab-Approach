import curses
import os
import subprocess
import logging
import ipaddress

# ------------------ Phase 3 Logger ------------------ #
phase3_logger = logging.getLogger("phase3_logger")
phase3_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
file_handler = logging.FileHandler('phase3.log')
file_handler.setFormatter(formatter)
phase3_logger.addHandler(file_handler)

##############################################
# Common Helper Functions (Printing, Input)  #
##############################################

def print_wrapped(screen, start_y, start_x, text, max_width):
    if len(text) > max_width:
        text = text[:max_width-1]
    screen.addstr(start_y, start_x, text)

def message_box(screen, message):
    screen.clear()
    screen.border(0)
    lines = message.split('\n')
    max_y, max_x = screen.getmaxyx()
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1
    if y < max_y - 2:
        print_wrapped(screen, y+1, 2, "Press any key to continue...", max_x - 4)
    screen.refresh()
    screen.getch()

def input_box(screen, prompt):
    curses.noecho()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()

    lines = prompt.split('\n')
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1

    print_wrapped(screen, y+1, 2, "(Press ESC or type 'back' to return)", max_x - 4)
    input_y = y + 3
    input_x = 2
    screen.move(input_y, input_x)
    screen.refresh()

    buffer = []
    curses.curs_set(1)
    while True:
        ch = screen.getch()
        if ch == 27:
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127):
            if buffer:
                buffer.pop()
                screen.delch(input_y, input_x + len(buffer))
        elif ch in (10, 13):
            user_input = "".join(buffer).strip()
            curses.curs_set(0)
            if user_input.lower() == "back":
                return None
            return user_input
        elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_UP, curses.KEY_DOWN):
            continue
        else:
            if 32 <= ch <= 126:
                buffer.append(chr(ch))
                screen.addch(input_y, input_x + len(buffer)-1, ch)

def run_command(cmd):
    """
    Run a shell command quietly, raise on failure.
    """
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

##################################
# Phase 3: OVS Utility Functions #
##################################

def check_ovs_installed():
    """
    Check if OVS (ovs-vsctl) is installed on the system.
    If not, attempt to install 'openvswitch-switch' quietly.
    Returns True if installed or installed successfully, False if it fails.
    """
    try:
        # 'which ovs-vsctl' will raise CalledProcessError if not found
        subprocess.check_output(["which", "ovs-vsctl"], stderr=subprocess.STDOUT)
        # If we get here, OVS is already installed
        phase3_logger.info("OVS is already installed on this system.")
        return True
    except subprocess.CalledProcessError:
        # Not installed, let's install
        phase3_logger.info("OVS is not installed. Attempting to install openvswitch-switch.")
        try:
            run_cmd(["apt-get", "update"])
            run_cmd(["apt-get", "install", "-y", "openvswitch-switch"])
            phase3_logger.info("Successfully installed openvswitch-switch.")
            return True
        except Exception as e:
            phase3_logger.error(f"Failed to install openvswitch-switch: {e}")
            return False

def bridge_exists(bridge_name):
    """
    Return True if an OVS bridge with 'bridge_name' already exists,
    otherwise False.
    Uses 'ovs-vsctl br-exists', which returns 0 if bridge exists,
    non-zero if not.
    """
    try:
        subprocess.check_call(["ovs-vsctl", "br-exists", bridge_name])
        return True  # if no error, bridge exists
    except subprocess.CalledProcessError:
        return False  # if error, means bridge doesn't exist

def interface_exists(iface_name):
    """
    Return True if network interface (port) 'iface_name' exists,
    otherwise False. Uses 'ip link show <iface_name>'.
    """
    try:
        subprocess.check_call(["ip", "link", "show", iface_name],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
##################################
# Phase 3: OVS Utility Functions #
##################################

def run_cmd(cmd):
    """
    Run a shell command quietly, raise on failure.
    """
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)


def check_ovs_installed():
    """
    Check if OVS (ovs-vsctl) is installed on the system.
    If not, attempt to install 'openvswitch-switch' quietly.
    Returns True if installed or installed successfully, False if it fails.
    """
    try:
        # 'which ovs-vsctl' will raise CalledProcessError if not found
        subprocess.check_output(["which", "ovs-vsctl"], stderr=subprocess.STDOUT)
        # If we get here, OVS is already installed
        phase3_logger.info("OVS is already installed on this system.")
        return True
    except subprocess.CalledProcessError:
        # Not installed, let's install
        phase3_logger.info("OVS is not installed. Attempting to install openvswitch-switch.")
        try:
            run_cmd(["apt-get", "update"])
            run_cmd(["apt-get", "install", "-y", "openvswitch-switch"])
            phase3_logger.info("Successfully installed openvswitch-switch.")
            return True
        except Exception as e:
            phase3_logger.error(f"Failed to install openvswitch-switch: {e}")
            return False

def bridge_exists(bridge_name):
    """
    Return True if an OVS bridge with 'bridge_name' already exists,
    otherwise False.
    Uses 'ovs-vsctl br-exists', which returns 0 if bridge exists,
    non-zero if not.
    """
    try:
        subprocess.check_call(["ovs-vsctl", "br-exists", bridge_name])
        return True  # if no error, bridge exists
    except subprocess.CalledProcessError:
        return False  # if error, means bridge doesn't exist

def interface_exists(iface_name):
    """
    Return True if network interface (port) 'iface_name' exists,
    otherwise False. Uses 'ip link show <iface_name>'.
    """
    try:
        subprocess.check_call(["ip", "link", "show", iface_name],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


###############################
# Creating/Deleting Bridges   #
###############################

def add_ovs_bridge(bridge_name):
    """
    Create a new OVS bridge using 'ovs-vsctl add-br'.
    """
    run_cmd(["ovs-vsctl", "add-br", bridge_name])
    phase3_logger.info(f"Created OVS Bridge: {bridge_name}")

def delete_ovs_bridge(bridge_name):
    """
    Delete an OVS bridge if it exists, otherwise raise an error.
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Bridge '{bridge_name}' does not exist.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")
    
    run_cmd(["ovs-vsctl", "del-br", bridge_name])
    phase3_logger.info(f"Deleted OVS Bridge: {bridge_name}")


########################
# Adding/Removing Ports
########################

def add_port_to_bridge(bridge_name, port_name):
    """
    Add a port to an OVS bridge, checking if both bridge and port exist.
    If port doesn't exist (system interface), fail. 
    For internal ports, user must specify 'type=internal' (see add_port_to_bridge_form).
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Cannot add port to non-existent bridge '{bridge_name}'.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")
    
    # If user said it's a system interface, we check if it exists
    # If it's an internal port, we skip - see add_port_to_bridge_form for logic
    # (In this function, we do not check again since we rely on the logic in the form.)
    
    # Just do it. If it fails, we catch the error above in the caller.
    run_cmd(["ovs-vsctl", "add-port", bridge_name, port_name])
    phase3_logger.info(f"Added port {port_name} to bridge {bridge_name}")

def remove_port_from_bridge(bridge_name, port_name):
    """
    Remove a port from a bridge. We rely on 'ovs-vsctl del-port' to fail if 
    either the bridge or port doesn't exist or if the port is not on that bridge.
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Bridge '{bridge_name}' does not exist.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")
    
    # Attempt removal. If port isn't on the bridge, this fails, 
    # and we catch the error in the caller.
    run_cmd(["ovs-vsctl", "del-port", bridge_name, port_name])
    phase3_logger.info(f"Removed port {port_name} from bridge {bridge_name}")


############################
# Up/Down, Trunk/Access
############################

def bring_port_up(port_name):
    """
    Bring a port up: 'ip link set <port> up'.
    """
    run_cmd(["ip", "link", "set", port_name, "up"])
    phase3_logger.info(f"Brought port {port_name} up")

def bring_port_down(port_name):
    """
    Bring a port down: 'ip link set <port> down'.
    """
    run_cmd(["ip", "link", "set", port_name, "down"])
    phase3_logger.info(f"Brought port {port_name} down")

def set_port_trunk(port_name, vlan_list):
    """
    Switch port to trunk mode by removing 'tag' and setting 'trunks'.
    Example: trunks=10,20,30
    """
    # First remove 'tag' if any
    run_cmd(["ovs-vsctl", "remove", "port", port_name, "tag"])
    # Then set trunk
    run_cmd(["ovs-vsctl", "set", "port", port_name, f"trunks={vlan_list}"])
    phase3_logger.info(f"Set port {port_name} as trunk with VLANs: {vlan_list}")

def set_port_access(port_name, vlan_id):
    """
    Switch port to access mode by removing 'trunks' config and setting 'tag'.
    Now uses '--if-exists remove' to avoid non-zero exit if no trunk existed.
    """
    run_cmd(["ovs-vsctl", "--if-exists", "remove", "port", port_name, "trunks"])
    run_cmd(["ovs-vsctl", "set", "port", port_name, f"tag={vlan_id}"])
    phase3_logger.info(f"Set port {port_name} as access on VLAN {vlan_id}")

def configure_ip_on_vlan_interface(vlan_interface, ip_address, subnet_mask):
    """
    Validate that 'vlan_interface' exists, then assign IP with 'ip' commands.
    """
    try:
        subprocess.check_call(["ip", "link", "show", vlan_interface])
    except subprocess.CalledProcessError:
        phase3_logger.error(f"VLAN interface '{vlan_interface}' not found.")
        raise ValueError(f"VLAN interface '{vlan_interface}' does not exist.")

    cidr = f"{ip_address}/{subnet_mask}"
    run_cmd(["ip", "addr", "flush", "dev", vlan_interface])
    run_cmd(["ip", "addr", "add", cidr, "dev", vlan_interface])
    run_cmd(["ip", "link", "set", vlan_interface, "up"])
    phase3_logger.info(f"Configured {vlan_interface} with IP {cidr}")


#######################
# Phase 3 TUI Menus   #
#######################

def add_ovs_bridge_form(screen):
    """
    Ask user for a bridge name, then create it if it doesn't exist.
    """
    br = input_box(screen, "Enter new OVS bridge name:")
    if br is None:
        return
    # 1. Check if bridge already exists:
    if bridge_exists(br):
        message_box(screen, f"Bridge '{br}' already exists!\nPlease choose another name.")
        phase3_logger.warning(f"Attempted to create existing bridge '{br}'.")
        return
    # 2. Create if doesn't exist
    try:
        add_ovs_bridge(br)
        message_box(screen, f"Created OVS bridge '{br}' successfully!")
    except Exception as e:
        phase3_logger.error(f"Error creating bridge {br}: {e}")
        message_box(screen, f"Error creating bridge:\n{e}")

def delete_ovs_bridge_form(screen):
    """
    Ask user for a bridge name, delete it.
    """
    br = input_box(screen, "Enter OVS bridge name to delete:")
    if br is None:
        return
    try:
        delete_ovs_bridge(br)
        message_box(screen, f"Deleted OVS bridge '{br}' successfully!")
    except Exception as e:
        phase3_logger.error(f"Error deleting bridge {br}: {e}")
        message_box(screen, f"Error deleting bridge:\n{e}")

def select_port_type(screen):
    """
    Ask user if the new port is a system interface or an internal port.
    Returns "system" or "internal", or None if user goes back.
    """
    options = ["System Port (already exists)", "OVS Internal Port", "Back"]
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Choose Port Type (ESC to go back)", max_x - 4)
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + opt, max_x - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:  # Enter
            if options[selected] == "Back":
                return None
            elif options[selected].startswith("System"):
                return "system"
            elif options[selected].startswith("OVS Internal"):
                return "internal"
        elif key == 27:  # ESC
            return None

def add_port_to_bridge_form(screen):
    """
    Ask user for a bridge, then ask for port name,
    then ask if it's system or internal,
    and add accordingly.
    """
    br = input_box(screen, "Enter OVS bridge name:")
    if br is None:
        return

    port_name = input_box(screen, "Enter port (interface) name to add:")
    if port_name is None:
        return

    port_type = select_port_type(screen)  # system or internal
    if port_type is None:
        return

    try:
        if not bridge_exists(br):
            message_box(screen, f"Bridge '{br}' does not exist!")
            phase3_logger.warning(f"User tried to add port to non-existent bridge '{br}'.")
            return

        if port_type == "system":
            # Check if underlying interface actually exists
            if not interface_exists(port_name):
                message_box(screen, f"Interface '{port_name}' does not exist!\nCannot add to OVS as a system port.")
                phase3_logger.warning(f"User tried adding non-existent system interface '{port_name}' to {br}.")
                return
            # Add an existing system interface
            run_cmd(["ovs-vsctl", "add-port", br, port_name])
            phase3_logger.info(f"Added existing system port '{port_name}' to bridge '{br}'")
        else:
            # internal
            # Creating an OVS internal port that does not exist yet
            run_cmd(["ovs-vsctl", "add-port", br, port_name,
                     "--", "set", "interface", port_name, "type=internal"])
            phase3_logger.info(f"Created internal port '{port_name}' on bridge '{br}'")

        message_box(screen, f"Port '{port_name}' added to bridge '{br}' as {port_type}.")
    except Exception as e:
        phase3_logger.error(f"Error adding port {port_name} to {br} as {port_type}: {e}")
        message_box(screen, f"Error adding port:\n{e}")

def remove_port_from_bridge_form(screen):
    """
    Ask user for bridge, port to remove.
    """
    br = input_box(screen, "Enter OVS bridge name:")
    if br is None:
        return
    prt = input_box(screen, "Enter port name to remove from bridge:")
    if prt is None:
        return
    try:
        remove_port_from_bridge(br, prt)
        message_box(screen, f"Removed port '{prt}' from bridge '{br}'.")
    except Exception as e:
        phase3_logger.error(f"Error removing port {prt} from bridge {br}: {e}")
        message_box(screen, f"Error removing port:\n{e}")

def bring_port_up_form(screen):
    prt = input_box(screen, "Enter port (interface) name to bring up:")
    if prt is None:
        return
    # Check if port actually exists:
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot bring it up.")
        phase3_logger.warning(f"User tried to bring up non-existent port '{prt}'.")
        return
    try:
        bring_port_up(prt)
        message_box(screen, f"Port '{prt}' is now up.")
    except Exception as e:
        phase3_logger.error(f"Error bringing port {prt} up: {e}")
        message_box(screen, f"Error:\n{e}")

def bring_port_down_form(screen):
    prt = input_box(screen, "Enter port (interface) name to bring down:")
    if prt is None:
        return
    # Check if port actually exists:
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot bring it down.")
        phase3_logger.warning(f"User tried to bring down non-existent port '{prt}'.")
        return
    try:
        bring_port_down(prt)
        message_box(screen, f"Port '{prt}' is now down.")
    except Exception as e:
        phase3_logger.error(f"Error bringing port {prt} down: {e}")
        message_box(screen, f"Error:\n{e}")

def set_port_trunk_form(screen):
    prt = input_box(screen, "Enter port name to set as trunk:")
    if prt is None:
        return
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot set trunk mode.")
        phase3_logger.warning(f"Attempted trunk on non-existent port '{prt}'.")
        return
    vlans = input_box(screen, "Enter comma-separated VLAN IDs (e.g. 10,20,30):")
    if vlans is None:
        return
    try:
        set_port_trunk(prt, vlans)
        message_box(screen, f"Set port '{prt}' trunk with VLANs '{vlans}'.")
    except Exception as e:
        phase3_logger.error(f"Error setting trunk mode on {prt}: {e}")
        message_box(screen, f"Error:\n{e}")

def set_port_access_form(screen):
    prt = input_box(screen, "Enter port name to set as access:")
    if prt is None:
        return
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot set access mode.")
        phase3_logger.warning(f"Attempted access mode on non-existent port '{prt}'.")
        return
    vlan_id_str = input_box(screen, "Enter single VLAN ID (e.g. 10):")
    if vlan_id_str is None:
        return
    if not vlan_id_str.isdigit():
        message_box(screen, "VLAN ID must be numeric!")
        return
    try:
        set_port_access(prt, vlan_id_str)
        message_box(screen, f"Set port '{prt}' as access on VLAN {vlan_id_str}.")
    except Exception as e:
        phase3_logger.error(f"Error setting access mode on {prt}: {e}")
        message_box(screen, f"Error:\n{e}")

def configure_ip_for_vlan_interface_form(screen):
    vlan_if = input_box(screen, "Enter VLAN interface name (e.g. 'br0.20' or 'vlan20'):")
    if vlan_if is None:
        return

    # If user typed just an integer, this is not a valid interface name.
    # You can either:
    # 1) Reject it:
    # if vlan_if.isdigit():
    #     message_box(screen, "Please specify a real interface name (e.g. br0.20).")
    #     return
    #
    # or 2) auto-create it (advanced logic)...

    if not interface_exists(vlan_if):
        phase3_logger.error(f"Interface '{vlan_if}' does not exist.")
        message_box(screen, f"Interface '{vlan_if}' does not exist!\n"
                            "If you meant to create it, do so under 'Add Port' with 'type=internal'.")
        return

    ip_str = input_box(screen, "Enter IP Address (e.g. 192.168.10.5):")
    if ip_str is None:
        return
    # Validate IP
    try:
        ipaddress.IPv4Address(ip_str)
    except:
        message_box(screen, "Invalid IP address!")
        return

    mask_str = input_box(screen, "Enter Subnet Mask in CIDR (0-32):")
    if mask_str is None:
        return
    if not mask_str.isdigit():
        message_box(screen, "Mask must be numeric.")
        return
    mask_int = int(mask_str)
    if mask_int < 0 or mask_int > 32:
        message_box(screen, "Mask out of range (0-32)!")
        return

    try:
        configure_ip_on_vlan_interface(vlan_if, ip_str, mask_int)
        message_box(screen, f"Configured VLAN interface '{vlan_if}' with {ip_str}/{mask_int}.")
    except Exception as e:
        phase3_logger.error(f"Error configuring IP on VLAN interface {vlan_if}: {e}")
        message_box(screen, f"Error:\n{e}")

############################
# Phase 3 TUI Menu         #
############################

def ovs_management_menu(screen):
    """
    Phase 3 TUI for OVS management.
    """
    # 1) Check if OVS installed
    if not check_ovs_installed():
        message_box(screen, "Failed to install Open vSwitch.\nCannot proceed with OVS management.")
        return

    selected = 0
    options = [
        "Add OVS Bridge",
        "Delete OVS Bridge",
        "Add Port to Bridge",
        "Remove Port from Bridge",
        "Bring Port Up",
        "Bring Port Down",
        "Set Port as Trunk",
        "Set Port as Access",
        "Configure IP for VLAN Interface",
        "Back to Main Menu"
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Phase 3: Open vSwitch Management (ESC to go back)", max_x - 4)

        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + opt, max_x - 4)

        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in (10, 13):
            if selected == 0:
                add_ovs_bridge_form(screen)
            elif selected == 1:
                delete_ovs_bridge_form(screen)
            elif selected == 2:
                add_port_to_bridge_form(screen)
            elif selected == 3:
                remove_port_from_bridge_form(screen)
            elif selected == 4:
                bring_port_up_form(screen)
            elif selected == 5:
                bring_port_down_form(screen)
            elif selected == 6:
                set_port_trunk_form(screen)
            elif selected == 7:
                set_port_access_form(screen)
            elif selected == 8:
                configure_ip_for_vlan_interface_form(screen)
            elif selected == 9:
                break
        elif key == 27:
            break


def ovs_management_menu(screen):
    if not check_ovs_installed():
        message_box(screen, "Failed to install OVS. Cannot proceed.")
        return
    selected = 0
    options = [
        "Add OVS Bridge",
        "Delete OVS Bridge",
        "Add Port to Bridge",
        "Remove Port from Bridge",
        "Bring Port Up",
        "Bring Port Down",
        "Set Port as Trunk",
        "Set Port as Access",
        "Configure IP for VLAN Interface",
        "Exit Phase 3"
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Phase 3: OVS Management (ESC to exit)", max_x - 4)
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + opt, max_x - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if selected == 0:
                add_ovs_bridge_form(screen)
            elif selected == 1:
                delete_ovs_bridge_form(screen)
            elif selected == 2:
                add_port_to_bridge_form(screen)
            elif selected == 3:
                remove_port_from_bridge_form(screen)
            elif selected == 4:
                bring_port_up_form(screen)
            elif selected == 5:
                bring_port_down_form(screen)
            elif selected == 6:
                set_port_trunk_form(screen)
            elif selected == 7:
                set_port_access_form(screen)
            elif selected == 8:
                configure_ip_for_vlan_interface_form(screen)
            elif selected == 9:
                break
        elif key == 27:
            break

def main(stdscr):
    if os.geteuid() != 0:
        stdscr.clear()
        stdscr.border(0)
        message_box(stdscr, "Error: Must run as root.\nPress any key to exit.")
        return
    ovs_management_menu(stdscr)

if __name__ == '__main__':
    curses.wrapper(main)