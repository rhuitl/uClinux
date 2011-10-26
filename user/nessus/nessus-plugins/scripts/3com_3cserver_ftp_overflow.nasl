#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16321);
 script_cve_id("CVE-2005-0276", "CVE-2005-0277", "CVE-2005-0278");
 script_bugtraq_id(12463, 12155);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "3Com 3CServer/3CDaemon FTP Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running the 3Com 3CServer or 3CDaemon FTP server.

There is a buffer overflow condition in the remote version of this
software. An attacker may exeploit this flaw to execute arbitrary code 
on the remote host with the privileges of the FTP server (root).

Solution : Upgrade to the latest version of this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 3Com 3CServer FTP Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nes");
 exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;

ftpbanner = get_ftp_banner(port:port);
if ( ftpbanner == NULL ) exit(0);
if ( egrep(pattern:"^220 3Com FTP Server Version 1\.[01]([^0-9]|\.)", string:ftpbanner) ||
     egrep(pattern:"^220 3Com 3CDaemon FTP Server Version [0-2]\.)", string:ftpbanner)) 
	security_hole(port);
