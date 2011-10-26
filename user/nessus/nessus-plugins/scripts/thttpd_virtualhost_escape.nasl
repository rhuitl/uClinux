#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11576);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(8924, 8906);
 script_cve_id("CVE-2002-1562", "CVE-2003-0899");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:044");
 
 name["english"] = "thttpd directory traversal thru Host:";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote HTTP server allows anyone to browse the files on the remote
host by sending HTTP requests with a Host: field set to '../../'.

Solution : Upgrade to thttpd 2.23 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "thttpd flaw";
 summary["francais"] = "Trou de sécurité de thttpd";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  req = string("GET / HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);

  list1 = NULL;
  if("mode  links  bytes  last-changed  name" >< res) { list1 = res; }

  req = string("GET / HTTP/1.1\r\n",
"Host: ", get_host_name(), "/..\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
 
  if("mode  links  bytes  last-changed  name" >< res)
	{
	if(!list1)security_hole(port);
	else 	{
		l = strstr(list1, string("\r\n\r\n"));
		m = strstr(res, string("\r\n\r\n"));
		#display(m);
		if(l != m)security_hole(port);
		}
 	}
}
