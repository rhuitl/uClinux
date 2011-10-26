#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Marc <marc@EEYE.COM>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14586);
 script_bugtraq_id(217);
 script_cve_id("CVE-1999-0362");
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"937");

 script_version ("$Revision: 1.4 $");
 name["english"] = "WS FTP CWD DoS";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its version number, your remote WS_FTP server is vulnerable to a 
denial of service.

A logged attacker submitting a 'CWD' command along with arbitrary characters 
will deny the ftp service.

** Nessus only checked the version number in the server banner

Solution : Upgrade to the latest version
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check WS_FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"WS_FTP Server 1\.0\.[0-2][^0-9]", string: banner))
	security_warning(port);
