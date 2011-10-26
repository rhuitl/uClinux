#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if (description) {
   script_id(10828);
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0014");
   script_bugtraq_id(3681);
   script_cve_id("CVE-2001-0797");
   script_version("$Revision: 1.13 $");
  name["english"] = "SysV /bin/login buffer overflow (rlogin)";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote /bin/login seems to crash when it receives too many
environment variables.

An attacker may use this flaw to gain a root shell on this system.

See also : http://www.cert.org/advisories/CA-2001-34.html
Solution : Contact your vendor for a patch (or read the CERT advisory)
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Attempts to overflow /bin/login";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");

  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes");
  script_require_ports("Services/rlogin", 513);
  exit(0);
}


#
# The script code starts here
#

port = get_kb_item("Services/rlogin");
if(!port)port = 513;


function rlogin(env)
{
if(get_port_state(port))
{
 soc = open_priv_sock_tcp(dport:port);
 if(soc)
 {
  s1 = raw_string(0);
  s2 = string("nessus", s1, s1);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
 
  a = recv(socket:soc, length:1, min:1);
 
  
  if(!strlen(a)){
  	return(0);
	}
  if(!(ord(a[0]) == 0)){
  	return(0);
	}
  send(socket:soc, data:s1);
  a = recv(socket:soc, length:1024, min:1);
  if("ogin:" >< a)
  {
    send(socket:soc, data:string(env, "\r\n"));
    a = recv(socket:soc, length:4096);
    a = recv(socket:soc, length:4096);
    if("word:" >< a)
    {
     close(soc);
     return(1);
    }
   }
   close(soc);
  }
  else return(0);
 }
 return(0);
}


if(rlogin(env:"nessus"))
{
res = rlogin(env:string("nessus ", crap(data:"A=B ", length:244)));
if(res)
 {
  res = rlogin(env:string("nessus ", crap(data:"A=B ", length:400)));
  if(!res)security_hole(port);
 }
}
