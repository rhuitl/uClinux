#
# written by Gareth Phillips - SensePost (www.sensepost.com)
# GPLv2
#
# changes by Tenable:
#  - Fixed regex
#
if(description)
{
 script_id(18627);
 script_cve_id("CVE-2005-1415");
 script_bugtraq_id (13454);
 script_version ("$Revision: 1.4 $");

 name["english"] = "GlobalSCAPE Secure FTP Server User Input Overflow";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running GlobalSCAPE Secure FTP Server.

GlobalSCAPE Secure FTP Server 3.0.2 and prior versions are affected by a buffer overflow 
due to mishandling the user-supplied input. 

An attacker would first need to authenticate to the server before they can execute 
arbitrary commands.

Solution: Upgrade to newest release of this software
Risk factor : High";
 script_description(english:desc["english"]);

 summary["english"] = "GlobalSCAPE Secure FTP Server User Input Overflow";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 SensePost");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}




#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

ftpbanner = get_ftp_banner(port:port);
if ( ftpbanner && egrep(pattern:"^220 GlobalSCAPE Secure FTP Server \(v. 3(.0|\.0\.[0-2])\)",string:ftpbanner) )security_hole(port);
