#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10205);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0651");
 name["english"] = "Rlogin Server Detection";
 script_name(english:name["english"]);
 
 
 desc["english"] = "
Synopsis :

The rlogin service is listening on the remote port.

Description :

The remote host is running the 'rlogin' service.  This service is dangerous in 
the sense that it is not ciphered - that is, everyone can sniff the data that 
passes between the rlogin client and the rloginserver. This includes logins 
and passwords.

Also, it may allow poorly authenticated logins without passwords. If the 
host is vulnerable to TCP sequence number guessing (from any network)
or IP spoofing (including ARP hijacking on a local network) then it may 
be possible to bypass authentication.

Finally, rlogin is an easy way to turn file-write access into full logins 
through the .rhosts or rhosts.equiv files. 

You should disable this service and use ssh instead.

Solution : 

Comment out the 'login' line in /etc/inetd.conf

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:C)";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of rlogin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 - 2006 Tenable Network Security");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rlogin", 513);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/rlogin");
if(!port){
	p = known_service(port:513);
	if(p && p != "rlogin")exit(0);
	port = 513;
	}

if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = "root" + raw_string(0) + "root" + raw_string(0) + "ls" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024, min:1);
  if(strlen(a))
   security_warning(port);
  else
   {
   a = recv(socket:soc, length:1024, min:1);
   if(strlen(a))
    security_warning(port);
   } 
  close(soc);
 }
}

