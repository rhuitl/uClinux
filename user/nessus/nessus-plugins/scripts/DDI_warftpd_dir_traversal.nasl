#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
	script_id(11206);
	script_bugtraq_id(2444);
	script_version("$Revision: 1.5 $");
	
	script_cve_id("CVE-2001-0295");
	
	name["english"] = "War FTP Daemon Directory Traversal";
	script_name(english:name["english"]);

	desc["english"] = "
The version of WarFTPd running on this host contains a vulnerability that
may allow a potential intruder to gain read access to directories and files
outside of the ftp root. By sending a specially crafted 'dir' command, 
the server may disclose an arbitrary directory.

Solution:
Visit the following link and download the latest version of WarFTPd:

ftp://ftp.jgaa.com/pub/products/Windows/WarFtpDaemon/

Risk factor: Low";

	script_description(english:desc["english"]);
	summary["english"] = "WarFTPd Directory Traversal";
	script_summary(english:summary["english"]);
	script_category(ACT_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2003 Digital Defense, Inc.");
	family["english"] = "FTP";
	script_family(english:family["english"]);
	script_dependencies("find_service_3digits.nasl");
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

	if( (egrep(pattern:"WAR-FTPD 1\.(6[0-5]|[0-5].*)",string:r)) || ("WAR-FTPD 1.67-04" >< r) )
	{
		security_hole(port);
	}
}
