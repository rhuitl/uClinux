#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10853);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2002-0569");
 script_bugtraq_id(4298);
 script_xref(name:"IAVA", value:"2002-t-0006");
 script_xref(name:"OSVDB", value:"710");

 name["english"] = "Oracle 9iAS mod_plsql cross site scripting";
 name["francais"] = "Oracle 9iAS mod_plsql cross site scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The mod_plsql module supplied with Oracle9iAS allows cross site scripting 
attacks to be performed.

Solution: 

Patches which address several vulnerabilities in Oracle 9iAS can be 
downloaded from the oracle Metalink site.

References:
http://www.nextgenss.com/papers/hpoas.pdf (Hackproofing Oracle9iAS)
http://www.oracle.com/

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle 9iAS mod_plsql cross site scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

req = http_get(item:"/pls/help/<SCRIPT>alert(document.domain)</SCRIPT>",
 		port:port);
soc = http_open_socket(port);
if(soc)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>");
 confirmedtoo = string("No DAD configuration");
  if((confirmed >< r) && (confirmedtoo >< r)) security_hole(port);
}

