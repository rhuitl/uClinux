#  
# (C) Tenable Network Security
#
if(description)
{
 script_id(12240);
 script_bugtraq_id(10384);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0396");
 
 
 name["english"] = "CVS pserver heap overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number, might allow an 
attacker to execute arbitrary commands on the remote system because
of a heap overflow in the cvs pserver code.

Solution : Upgrade to CVS 1.12.8 or 1.11.16
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nes", "cvs_public_pserver.nasl");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

login = get_kb_item(string("cvs/", port, "/login"));
pass  = get_kb_item(string("cvs/", port, "/pass"));
dir   = get_kb_item(string("cvs/", port, "/dir"));

if(!login || !dir) {
	if ( report_paranoia < 1 ) exit(0);
	soc = open_sock_tcp(port);
	if(!soc)exit(0);

	req = string("BEGIN AUTH REQUEST\n",
	"/\n",
	"\n",
	"A\n",
	"END AUTH REQUEST\n");
	send(socket:soc, data:req);
	r = recv_line(socket:soc, length:4096);
	if("repository" >< r || "I HATE" >< r)
		{
		str = 
string("The remote host is running a CVS server on this port, but
Nessus could not determine which version is running.

Some remote CVS servers might allow an attacker to execute arbitrary 
commands on the remote system because of a heap overflow in the cvs 
pserver code.

*** This may be a false positive, check the version of CVS locally

Solution : Upgrade to CVS 1.12.8 or 1.11.16
Risk factor : High");

		security_hole(port:port, data:str);
		}
	}

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("BEGIN AUTH REQUEST\n",
dir, "\n",
login,"\n",
"A", pass,"\n",
"END AUTH REQUEST\n");

  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  if("I LOVE YOU" >< r)
  {
    send(socket:soc, data:string("version\n"));
    r = recv_line(socket:soc, length:4096);
    if("Concurrent" >< r)
    {
     set_kb_item(name:string("cvs/", port, "/version"), value:r);
     if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-5])|12\.[0-7][^0-9]).*", string:r))
     	security_hole(port);
    }
  }
  close(soc);
 
