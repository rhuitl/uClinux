#
# (C) Tenable Network Security
# 
# v1.2: 10/19/2004 KK Liu adjust to remove false-potive on XP hosts 

if(description)
{
 script_id(15464);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0013");
 script_bugtraq_id(11374);
 script_cve_id("CVE-2004-0840");
 script_version ("$Revision: 1.6 $");
 name["english"] = "MS SMTP Vulnerability (885881)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft SMTP server which is
vulnerable to a buffer overflow issue.

An attacker may exploit this flaw to execute arbitrary commands on the remote
host with the privileges of the SMTP server process.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-035.mspx
Risk factor : High";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the remote SMTP daemon version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);

if ( "Microsoft ESMTP MAIL Service, Version: " >< banner )
{
 version = egrep(string:banner, pattern:"Microsoft ESMTP MAIL Service, Version: ");
 version = ereg_replace(string:version, pattern:".*Microsoft ESMTP MAIL Service, Version: (.*) ready", replace:"\1");
 ver = split(version, sep:".", keep:0);
 # KK Liu
 #5.0.2195 - Windows 2000
 #6.0.2600 - Windows XP
 #6.0.3790 - Windows 2003
 #6.0.6249 - Exchange 2000 SP3
 #6.0.3790.0 - Exchange 2003
 if ( int(ver[0]) == 6 )
 {
  if (int(ver[2]) > 2600) # KK Liu - only Win2003, WinXP2003 & Win2K+Exg2003, XP not affected
  {
  	if ( int(ver[1]) == 0 && ( int(ver[2]) < 3790 || ( int(ver[2]) == 3790 && int(ver[3]) < 211 ) ) ) security_hole(port);
  }
 }
}
