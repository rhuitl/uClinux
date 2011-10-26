#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: D4rkGr3y
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14659);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Titan FTP Server directory traversal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Titan FTP Server.  All versions up to and 
including 2.02 are reported vulnerable to directory traversal flaw.

An attacker could send specially crafted URL to view arbitrary files on the 
system.

Solution : Upgrade to latest version
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check Titan FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#the code

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"^220.*Titan FTP Server ([0-1]\.|2\.0[12][^0-9])", string:banner) ) 
	security_warning(port);
