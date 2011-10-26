#
# This plugin was written by Renaud Deraison <deraison@nessus.org> and
# is released under the GPL.

#
# Sun's patch makes /bin/login exits when it receives too many arguments,
# hence making the detection of the flaw difficult. Our logic is the
# following :
#
# Username: "nessus" -> should not crash
# Username: "nessus A=B..... x 61"  -> should not crash
# Username: "nessus A=B..... x 100" -> should crash
#

if (description) {
   script_id(10827);
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0014");
   script_bugtraq_id(3681, 7481);
   script_cve_id("CVE-2001-0797");
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0004");
   script_version("$Revision: 1.13 $");
  name["english"] = "SysV /bin/login buffer overflow (telnet)";
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
  script_require_ports("Services/telnet", 23);
  exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port) port = 23;
if(!get_port_state(port))exit(0);

function login(env)
{
soc = open_sock_tcp(port);
if(soc)
{
 buffer = telnet_negotiate(socket:soc);
 send(socket:soc, data:string("nessus ", env, "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if("word:" >< r)
  {
	return(1);
  }
 }
 return(0);
}



if(login(env:""))
{
 my_env = crap(data:"A=B ", length:244);
 res = login(env:my_env);
 if(res)
 {
  my_env = crap(data:"A=B ", length:400);
  res = login(env:my_env);
  if(!res)security_hole(port);
 }
}
