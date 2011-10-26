#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Refs:
#  From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: Multiple Buffer Overflow Vulnerabilities in SLMail (#NISR07052003A)
#  Date: Wed, 7 May 2003 17:44:22 +0100
#
# 
# The other issues (POP and POPPASSWD) should be covered by miscflood and pop3_overflows.nasl

if(description)
{
 script_id(11593);
 script_bugtraq_id(7512, 7515, 7519, 7525, 7526);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0264");

 
 name["english"] = "SLMail SMTP overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the SLmail 
SMTP server which is vulnerable to various overflows
which may allow to execute arbitrary commands on this
host or to disable it remotely.

Solution : Upgrade to SLMail 5.1.0.4433 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows the remote SMTP server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "sendmail_expn.nasl");
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

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!egrep(pattern:"^220 .*", string:s))
  {
   close(soc);
   exit(0);
  }
  
  if( safe_checks() )
  {
   if(egrep(pattern:"^220 .*SMTP Server SLmail ([0-4]\.|5\.(0\.|1\.0\.([0-9][0-9]?[0-9]?[^0-9]|([0-3]|4([0-3]|4([0-2]|3[0-2]))))))",
   	    string:s))security_hole(port);
   exit(0);	    
  }
  
  
  c = string("EHLO ", crap(1999), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  close(soc);
  
  soc = open_sock_tcp(port);
  if(!soc){security_hole(port); exit(0);}
 }
}
