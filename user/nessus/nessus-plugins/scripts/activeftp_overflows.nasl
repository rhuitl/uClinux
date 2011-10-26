#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11757);
 script_bugtraq_id(7900);
 script_version ("$Revision: 1.4 $");
 
 
 name["english"] = "NGC ActiveFTP Denial of Service";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Active FTP server, a shareware
FTP server for Windows-based systems.

There is a flaw in the version of ActiveFTP which is running which
may allow an attacker to crash this service remotely by sending
an overly long argument to various FTP commands (USER, CWD, and more).

Solution : None at this time. Use another FTP daemon
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "NGC ActiveFTP check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port)) exit(0);


#
# This service can not be crashed reliably, we only rely on the banner 
# (ie: no safe_checks/no safe checks).
#

banner = get_ftp_banner(port:port);
if(!banner) exit(0);
if("Welcome to NGC Active FTPServer" >< banner) { security_warning(port); exit(0); }
