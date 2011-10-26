#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : lion 
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14584);
 script_cve_id("CVE-2004-1643");
 script_bugtraq_id(11065);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"9382");
 script_version ("$Revision: 1.13 $");
 name["english"] = "WS FTP server DoS";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote FTP server is prone to a denial of service attack.

Description :

According to its banner, the version of WS_FTP on the remote host is
vulnerable to a remote denial of service. 

There is an error in the parsing of file paths.  Exploitation of this
flaw may cause a vulnerable system to use a large amount of CPU
resources. 

See also :

http://www.securityfocus.com/archive/1/373420
http://www.ipswitch.com/support/ws_ftp-server/releases/wr503.asp

Solution : 

Upgrade to WS_FTP Server 5.03 or later.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";

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

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-2][^0-9])", string: banner))
	security_note(port);
