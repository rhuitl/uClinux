#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15857);
 script_bugtraq_id(11772);
 script_version ("$Revision: 1.2 $");
 name["english"] = "WS FTP server multiple flaws (2)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its version number, the remote WS_FTP server is vulnerable to 
multiple buffer overflows which may be used by an attacker to execute arbitary
code on the remote system.

Solution : Upgrade to the latest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-3][^0-9])", string: banner))
	security_hole(port);
