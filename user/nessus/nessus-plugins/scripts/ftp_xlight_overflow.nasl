#
# (C) Tenable Network Security
# 
# Ref:
# From: "intuit e.b." <intuit@linuxmail.org>
# To: bugtraq@securityfocus.com
# Date: Sun, 15 Feb 2004 20:51:45 +0800
# Subject: Xlight ftp server 1.52 RETR bug


if(description)
{
 script_id(12056);
 script_cve_id("CVE-2004-0255", "CVE-2004-0287");
 script_bugtraq_id(9585, 9627, 9668);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "xlight FTP Server RETR Stack Overflow Vulnerability";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running XLight FTP server.

There is a bug in the way this server handles arguments to the RETR 
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

Solution : Upgrade XLight Server, at least to version 1.53.
Risk factor : High";
		 
		 
 script_description(english:desc["english"]);

 
 script_summary(english:"X-Light Stack Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"Xlight server v(0\..*|1\.([0-4][0-9]|5[0-2])[^0-9])", string:banner))security_hole(port);
