#
# (C) Tenable Network Security
#
# Ref:
# 
# Date: Thu, 31 Jul 2003 18:16:03 +0200 (CEST)
# From: Janusz Niewiadomski <funkysh@isec.pl>
# To: vulnwatch@vulnwatch.org, <bugtraq@securityfocus.com>
# Subject: [VulnWatch] wu-ftpd fb_realpath() off-by-one bug


if(description)
{
 script_id(11811);
 script_bugtraq_id(8315);
 script_cve_id("CVE-2003-0466");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:245-01");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:032");

 script_version ("$Revision: 1.7 $");

 
 name["english"] = "wu-ftpd fb_realpath() off-by-one overflow";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote Wu-FTPd server seems to be vulnerable to an off-by-one
overflow when dealing with huge directory structures.

An attacker may exploit this flaw to obtain a shell on this host.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.
*** Since Wu-FTPd 2.6.3 has not been released yet and only
*** patches are available to fix this issue, this might be 
*** a false positive.

Solution : Upgrade to Wu-FTPd 2.6.3 when available or apply the
patches available at http://www.wu-ftpd.org

Risk factor : High";
		
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) exit(0);


#if((!login) || safe_checks())
{
 if(egrep(pattern:".*wu-(2\.(5\.|6\.[012])).*",
 	 string:banner))security_hole(port);
  exit(0);
}

#
# To be done : real exploitation of this flaw
#
