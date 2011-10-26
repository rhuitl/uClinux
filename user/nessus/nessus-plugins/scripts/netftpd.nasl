#
# This script is (C) Tenable Network Security
#

if(description)
{
 script_id(18142);
 script_cve_id("CVE-2005-1323");
 script_bugtraq_id(13396);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"15865");
 }
 script_version ("$Revision: 1.3 $");
 name["english"] = "Intersoft NetTerm Netftpd USER Buffer Overflow Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running NetTerm Netftpd server.

There is a buffer overflow condition in the remote version of this
software. An attacker may exploit this flaw to execute arbitrary code 
on the remote host with the privileges of the FTP server.

Solution : Remove this software (no longer supported).

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for NetTerm Netftpd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
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
if ( ftpbanner == NULL ) exit(0);
if ( egrep(pattern:"^220 NetTerm FTP server ready", string:ftpbanner) )
	security_hole(port);
