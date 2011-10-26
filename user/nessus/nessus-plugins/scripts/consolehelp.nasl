#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# Modifications by Tenable Network Security :
# -> Check for an existing .jsp file, instead of /default.jsp
# -> Expect a jsp signature
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11724);
 script_bugtraq_id(1518);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2000-0682");
 script_xref(name:"OSVDB", value:"1481");
 
 
 name["english"] = "WebLogic source code disclosure";
 name["francais"] = "WebLogic source code disclosure";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There is a bug in the Weblogic web application.  Namely,
by inserting a /ConsoleHelp/ into a URL, critical source code
files may be viewed.

Solution : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA02-03.jsp
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WebLogic file disclosures ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

jspfiles = get_kb_list(string("www/", port, "/content/extensions/jsp"));

if(isnull(jspfiles))jspfiles = make_list("default.jsp");
else jspfiles = make_list(jspfiles);

cnt = 0;

foreach file (jspfiles)
{ 
 req = http_get(item:"/ConsoleHelp/" + file, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( "<%" >< res && "%>" >< res ) { security_hole(port); exit(0); }
 cnt ++;
 if(cnt > 10)exit(0);
}
