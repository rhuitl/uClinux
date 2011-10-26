#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
	script_id(11207);
	script_bugtraq_id(10078);
	script_cve_id("CVE-1999-0256");
	script_version("$Revision: 1.5 $");
	
	name["english"] = "War FTP Daemon USER/PASS Overflow";
	script_name(english:name["english"]);
	desc["english"] = "
The version of War FTP Daemon running on this host contains
a buffer overflow in the code that handles the USER and PASS
commands. A potential intruder could use this vulnerability
to crash the server, as well as run arbitrary commands on
the system.

Solution : Upgrade to the latest release of the War FTP Daemon
           available from the following web site: http://www.jgaa.com/

Risk factor : High";

	script_description(english:desc["english"]);
	summary["english"] = "War FTP Daemon USER/PASS Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003 Digital Defense, Inc.");
	family["english"] = "FTP";
	script_family(english:family["english"]);
	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);

	if(egrep(pattern:"WAR-FTPD 1.([0-5][0-9]|6[0-5])[^0-9]*Ready",string:r, icase:TRUE))
	{
		security_hole(port);
	}
}
