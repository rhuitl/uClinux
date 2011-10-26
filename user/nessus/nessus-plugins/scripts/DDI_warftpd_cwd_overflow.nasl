#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
	script_id(11205);
	script_bugtraq_id(966);
	script_version("$Revision: 1.4 $");
	
	script_cve_id("CVE-2000-0131");

	name["english"] = "War FTP Daemon CWD/MKD Buffer Overflow";
	script_name(english:name["english"]);
	desc["english"] = "
The version of the War FTP Daemon running on this host is vulnerable to a
buffer overflow attack. This is due to improper bounds checking within the
code that handles both the CWD and MKD commands. By exploiting this 
vulnerability, it is possible to crash the server, and potentially run 
arbitrary commands on this system.

Solution:
Visit the following link and download the latest version of WarFTPd:

ftp://ftp.jgaa.com/pub/products/Windows/WarFtpDaemon/

Risk factor: High";

	script_description(english:desc["english"]);
	summary["english"] = "War FTP Daemon CWD/MKD Buffer Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2003 Digital Defense, Inc.");
	family["english"] = "FTP";
	script_family(english:family["english"]);
	script_require_ports("Services/ftp", 21);
	script_dependencies("find_service_3digits.nasl");
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);
	
	if(("WAR-FTPD 1.66x4" >< r) || ("WAR-FTPD 1.67-03" >< r))
	{
		security_hole(port);
	}
}
