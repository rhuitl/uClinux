#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
#

if(description)
{
   script_id(11006);
   script_bugtraq_id(2395);
   script_version ("$Revision: 1.9 $");
   script_cve_id("CVE-2001-0309");
   name["english"] = "RedHat 6.2 inetd";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host has a bug in its 'inetd' server. 'inetd' is the
'internet super-server' and is in charge of managing multiple sub-servers
(like telnet, ftp, chargen, and more).

There is a bug in the inetd server that comes with RedHat 6.2, which allows 
an attacker to prevent it from working completely by forcing it to consume
system resources.

Solution : Upgrade to inetd-0.16-7
Risk factor : Medium";


   script_description(english:desc["english"]);
 
   summary["english"] = "Stalls the remote inetd";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(7,9,13,19,23,37);
   script_dependencies("find_service.nes");
   script_timeout(0);
   exit(0);
}


#
# The code starts here
# 
include("telnet_func.inc");
include("global_settings.inc");

do_check = 0; #thorough_tests;

  ret[0] = 0;
  n = 0;

  if(get_port_state(7))
  {
    soc = open_sock_tcp(7);
    if(soc){
      close(soc);
      ret[n] = 7;
      n = n + 1;
    }
  }

  if(get_port_state(9))
  {
    soc = open_sock_tcp(9);
    if(soc){
      close(soc);
      ret[n] = 9;
      n = n + 1;
    }
  }

  if(get_port_state(13))
  {
    soc = open_sock_tcp(13);
    if(soc){
      close(soc);
      ret[n] = 13;
      n = n + 1;
    }
  }

  if(get_port_state(19))
  {
    soc = open_sock_tcp(19);
    if(soc){
      close(soc);
      ret[n] = 19;
      n = n + 1;
    }
  }
  if(get_port_state(37))
  {
    soc = open_sock_tcp(37);
    if(soc){
      close(soc);
      ret[n] = 37;
      n = n + 1;
    }
  }

if(!n)exit(0);


if(!do_check)
{
 port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(!get_port_state(port))exit(0);
 buf = get_telnet_banner(port: port);
 if (buf)
 {
  if("Red Hat Linux release 6.2" >< buf)
  {
  report = string("
There is a bug in the inetd server that comes with
RedHat 6.2, which allows an attacker to prevent it
from working completely by forcing it to consume
system resources.

*** As the banner was used to determine this vulnerability, 
*** this might be a false positive

Solution : Upgrade to inetd-0.16-7
Risk factor : Medium");
   security_warning(port:23,
   		    data:report);
  }
 }
 exit(0);
}




for(i=0;i<1500;i=i+n)
{
 #
 # We *must* sleep 3 seconds between each connection,
 # or else inetd will close the port
 #
  sleep(3);
  for(j=0;j<n;j=j+1)
  {
  soc = open_sock_tcp(ret[j]);
  
  if(!(ret[j] == 9))
  {
   send(socket:soc, data:"foo\r\n");
   r = recv(socket:soc, length:5);
   if(!r){
   	security_warning(ret[j]);
	exit(0);
	}
  }
  close(soc);
  }
}
