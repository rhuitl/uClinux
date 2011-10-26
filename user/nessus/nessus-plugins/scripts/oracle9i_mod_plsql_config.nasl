#
# This script was written by Renaud Deraison
#

if(description)
{
 script_id(11452);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2002-0561");
 script_bugtraq_id(4292);
 script_xref(name:"IAVA", value:"2002-t-0006");
 script_xref(name:"OSVDB", value:"9472");

 name["english"] = "Oracle 9iAS web admin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Oracle 9i Application Server uses Apache as it's web
server with an Apache module for PL/SQL support.

By default, no authentication is required to access the
DAD configuration page. An attacker may use this flaw
to modify PL/SQL applications or prevent the remote host
from working properly.

Solution: Access to the relevant page can be restricted by
editing the file /Apache/modplsql/cfg/wdbsvr.app

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Oracle 9iAS mod_plsql admin page";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 7777);
 script_require_keys("www/OracleApache");
 exit(0);
}

#
# The script code starts here
# 

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:7777);

foreach port (ports)
{
 if(get_port_state(port))
 {
  req = http_get(item:"/pls/simpledad/admin_/gateway.htm?schema=sample", port:port);
  res = http_keepalive_send_recv(port:port, data:req); 
 
  if("Gateway Configuration" >< res){ security_hole(port); exit(0); }
 }
}

