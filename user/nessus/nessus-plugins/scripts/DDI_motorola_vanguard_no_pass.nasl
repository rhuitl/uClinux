#
# This script was written by Geoff Humes <geoff.humes@digitaldefense.net>
#
# See the Nessus Scripts License for details
#


if(description)
{
	script_id(11203);
	script_version("$Revision: 1.4 $");
	script_cve_id("CVE-1999-0508");
	name["english"] = "Motorola Vanguard with No Password";
	script_name(english:name["english"]);
 
	desc["english"] = "

This device is a Motorola Vanguard router and has 
no password set. An attacker can reconfigure 
this device without providing any authentication.

Solution: Please set a strong password for this device.

Risk factor: High";

	script_description(english:desc["english"]);
 
	summary["english"] = "Attempts to log into Vanguards.";
	script_summary(english:summary["english"]);
 
	script_category(ACT_GATHER_INFO);
 
	script_copyright(english:"This script is Copyright (C) 2003 Digital Defense");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_require_ports(23);
 
	exit(0);
}

include('telnet_func.inc');

function greprecv(socket, pattern)
{
 buffer = "";
 cnt = 0;
 while(1)
 {
  _r = recv_line(socket:soc, length:4096);
  if(strlen(_r) == 0)return(0);
  buffer = string(buffer, _r);
  if(ereg(pattern:pattern, string:_r))return(buffer);
  cnt = cnt + 1;
  if(cnt > 1024)return(0);
 }
}

#
# The script code starts here
#
port = 23;


if(get_port_state(port))
{
	banner = get_telnet_banner(port:port);
	if ( ! banner || "OK" >!< banner ) exit(0);

	soc = open_sock_tcp(port);
	if(soc)
	{
		buf = greprecv(socket:soc, pattern:".*OK.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("atds0\r\n"));
		buf = greprecv(socket:soc, pattern:".*Password.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("\r\n"));
		buf = greprecv(socket:soc, pattern:".*Logout.*");
		if(buf)security_hole(port);
		close(soc);
	}
}
