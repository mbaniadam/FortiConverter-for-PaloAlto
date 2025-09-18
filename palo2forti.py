import sys
import xml.etree.ElementTree as ET
import ipaddress
from pathlib import Path
import os, sys

# Set the directory to the script's location
os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
# Input Palo Alto XML
PA_XML = Path("merged-running-config.xml")

# Output directory (adjust if needed)
OUT_DIR = Path("Output")
OUT_DIR.mkdir(parents=True, exist_ok=True)

f_addr          = (OUT_DIR / "converted_addrs.txt").open("w")
f_addrgrp       = (OUT_DIR / "converted_grp.txt").open("w")
f_services      = (OUT_DIR / "converted_ports.txt").open("w")
f_interfaces    = (OUT_DIR / "vlans.txt").open("w")
f_policies      = (OUT_DIR / "converted_policies.txt").open("w")
f_schedules     = (OUT_DIR / "converted_schedules.txt").open("w")

# Helpers
def txt(e, path):
    n = e.find(path)
    return n.text.strip() if n is not None and n.text else ""

def members(parent):
    return [m.text.strip() for m in parent.findall("member")] if parent is not None else []

def forti_sanitize(name):
    return name.replace(" ", "_")[:63]

# Parse XML
tree = ET.parse(PA_XML)
root = tree.getroot()

# Typical base path
vsys = root.find("./devices/entry/vsys/entry")
if vsys is None:
    raise SystemExit("Could not locate vsys configuration in XML.")

# ---------------- Addresses ----------------
for a in vsys.findall("./address/entry"):
    name = forti_sanitize(a.get("name", "NONAME"))
    ip_net = txt(a, "ip-netmask")
    desc = txt(a, "description") or "''"
    if not ip_net:
        fqdn = txt(a, "fqdn")
        if fqdn:
            f_addr.write(f"edit {name}\nset type fqdn\nset fqdn {fqdn}\nset comment {desc}\nnext\n")
        continue
    f_addr.write(f"edit {name}\nset subnet {ip_net}\nset comment {desc}\nnext\n")

# ------------- Address Groups --------------
for g in vsys.findall("./address-group/entry"):
    name = forti_sanitize(g.get("name", "NONAME"))
    static = g.find("static")
    if static is None:
        continue
    for m in members(static):
        f_addrgrp.write(f"edit {name}\nappend member {forti_sanitize(m)}\nnext\n")

# ------------- Services --------------------
services_root = vsys.find("./service")
if services_root is not None:
    for s in services_root.findall("./entry"):
        name = forti_sanitize(s.get("name", "NONAME"))
        proto = s.find("./protocol")
        if proto is None:
            continue
        tcp = proto.find("tcp")
        udp = proto.find("udp")
        if tcp is not None:
            port = txt(tcp, "port")
            if port:
                f_services.write(f"edit {name}\nset tcp-portrange {port}\nnext\n")
        if udp is not None:
            port = txt(udp, "port")
            if port:
                f_services.write(f"edit {name}\nset udp-portrange {port}\nnext\n")

# ----------- Service Groups (flatten) ------
for sg in vsys.findall("./service-group/entry"):
    name = forti_sanitize(sg.get("name", "NONAME"))
    for m in members(sg.find("members")):
        # FortiGate usually: edit group; append member serviceX (would need separate section)
        # Here we just output comment showing relation
        f_services.write(f"# service-group {name} member {forti_sanitize(m)}\n")

# ------------- Interfaces (Layer3 + VLANs) -
net_if_root = root.find("./devices/entry/network/interface")
if net_if_root is not None:
    for eth in net_if_root.findall("./ethernet/entry"):
        eth_name = eth.get("name")
        lyr3 = eth.find("./layer3")
        if lyr3 is None:
            continue
        ip_container = lyr3.find("ip")
        if ip_container is None:
            continue
        for ip_entry in ip_container.findall("./entry"):
            cidr = ip_entry.get("name")
            if not cidr:
                continue
            try:
                iface_ip = ipaddress.ip_interface(cidr)
                net = iface_ip.network
            except ValueError:
                continue
            forti_if_name = forti_sanitize(f"{eth_name}_{net.network_address}_{net.prefixlen}")
            f_interfaces.write(f"edit {forti_if_name}\n")
            f_interfaces.write("set vdom 'root'\n")
            f_interfaces.write(f"set ip {cidr}\n")
            zone = txt(lyr3, "zone")
            if zone:
                f_interfaces.write(f"set alias {zone}\n")
            f_interfaces.write("set allowaccess ping\nset status up\n")
            f_interfaces.write("next\n")

# ------------- Schedules -------------------
sched_root = vsys.find("./schedule")
if sched_root is not None:
    day_map = {
        "mon":"monday","tue":"tuesday","wed":"wednesday",
        "thu":"thursday","fri":"friday","sat":"saturday","sun":"sunday"
    }
    for sch in sched_root.findall("./entry"):
        name = forti_sanitize(sch.get("name","NONAME"))
        f_schedules.write(f"edit {name}\n")
        rect = sch.find("./schedule-type/recurring")
        if rect is not None:
            # Collect weekdays (each weekday node holds time members)
            days_used = []
            start_time = end_time = None
            for wk in rect:
                if wk.tag in day_map:
                    times = members(wk.find("time"))
                    if times:
                        t = times[0]
                        if "-" in t:
                            start_time, end_time = t.split("-",1)
                    days_used.append(day_map[wk.tag])
            if days_used and start_time and end_time:
                f_schedules.write(f"set day {' '.join(days_used)}\n")
                f_schedules.write(f"set start {start_time}\nset end {end_time}\n")
        else:
            # absolute not implemented fully
            f_schedules.write("set schedule-type recurring\nset day monday tuesday wednesday thursday friday saturday sunday\nset start 00:00\nset end 23:59\n")
        f_schedules.write("next\n")

# ------------- Security Policies -----------
rulebase = vsys.find("./rulebase/security/rules")
policy_id = 1
if rulebase is not None:
    for rule in rulebase.findall("./entry"):
        name = forti_sanitize(rule.get("name","rule"))
        disabled = txt(rule, "disabled") == "yes"
        if disabled:
            continue
        from_zones = members(rule.find("from"))
        to_zones   = members(rule.find("to"))
        srcs       = members(rule.find("source")) or ["any"]
        dsts       = members(rule.find("destination")) or ["any"]
        services   = members(rule.find("service")) or ["any"]
        schedule   = txt(rule, "schedule") or "always"
        action     = txt(rule, "action") or "deny"
        # Map
        srcaddr = "all" if srcs == ["any"] else " ".join(map(forti_sanitize, srcs))
        dstaddr = "all" if dsts == ["any"] else " ".join(map(forti_sanitize, dsts))
        svc = "ALL" if services == ["any"] or services == ["application-default"] else " ".join(map(forti_sanitize, services))
        srcintf = " ".join(map(forti_sanitize, from_zones)) if from_zones else "any"
        dstintf = " ".join(map(forti_sanitize, to_zones)) if to_zones else "any"
        act = "accept" if action == "allow" else "deny"
        f_policies.write(f"edit {policy_id}\n")
        f_policies.write(f"set name {name}-P{policy_id}\n")
        f_policies.write(f"set srcintf {srcintf}\n")
        f_policies.write(f"set dstintf {dstintf}\n")
        f_policies.write(f"set srcaddr {srcaddr}\n")
        f_policies.write(f"set dstaddr {dstaddr}\n")
        f_policies.write(f"set schedule {forti_sanitize(schedule)}\n" if schedule != "always" else "set schedule always\n")
        f_policies.write(f"set service {svc}\n")
        f_policies.write(f"set action {act}\n")
        if act == "accept":
            f_policies.write("set utm-status enable\nset ssl-ssh-profile 'certificate-inspection'\nset ips-sensor 'BM'\n")
        f_policies.write("set logtraffic all\nnext\n")
        policy_id += 1

# Close files
for fh in (f_addr, f_addrgrp, f_services, f_interfaces, f_policies, f_schedules):
    fh.close()
