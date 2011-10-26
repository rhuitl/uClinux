#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10245);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0651");

 name["english"] = "Rsh Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The rsh service is running.

Description :

The remote host is running the 'rsh' service.  This service is dangerous in 
the sense that it is not ciphered - that is, everyone can sniff the data 
that passes between the rsh client and the rsh server. This includes logins 
and passwords.

Also, it may allow poorly authenticated logins without passwords. If the 
host is vulnerable to TCP sequence number guessing (from any network)
or IP spoofing (including ARP hijacking on a local network) then it may 
be possible to bypass authentication.

Finally, rsh is an easy way to turn file-write access into full logins 
through the .rhosts or rhosts.equiv files. 

You should disable this service and use ssh instead.

Solution : 

Comment out the 'rsh' line in /etc/inetd.conf

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of rsh";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rsh", 514);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = get_kb_item("Services/rsh");
if(!port)port = 514;

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "root" + raw_string(0) + "root" + raw_string(0) + "xterm/38400" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024);
  if(strlen(a)){
	set_kb_item(name:"rsh/active", value:TRUE);
    register_service(port: port, proto: "rsh");
    security_warning(port);
  }
  else {
    a = recv(socket:soc, length:1024);
    if(strlen(a))
    {
     set_kb_item(name:"rsh/active", value:TRUE);
     security_warning(port);
     register_service(port: port, proto: "rsh");
    }
  }
  close(soc);
 }
}
