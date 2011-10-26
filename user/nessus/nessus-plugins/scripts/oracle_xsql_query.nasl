#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to www.kb.cert.org
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10613);
 script_version ("$Revision: 1.12 $");
 name["english"] = "Oracle XSQL Sample Application Vulnerability";
 name["francais"] = "Oracle XSQL Sample Application Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "One of the sample applications that comes with 
the Oracle XSQL Servlet allows an attacker to make arbitrary queries to 
the Oracle database (under an unprivileged account). 
Whilst not allowing an attacker to delete or modify database contents, 
this flaw can be used to enumerate database users and view table names.

Solution: Sample applications should always be removed from 
production servers.

Reference : http://www.kb.cert.org/vuls/id/717827

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle XSQL Sample Application Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore",
		francais:"Ce script est Copyright (C) 2001 Matt Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Checqueryk starts here
# Check uses a default sample page supplied with the XSQL servlet. 

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/xsql/demo/adhocsql/query.xsql?sql=select%20username%20from%20ALL_USERS", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if("USERNAME" >< r)	
 	security_hole(port);
}
