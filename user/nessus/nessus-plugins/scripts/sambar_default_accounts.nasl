#
# This script was written by Renaud Deraison
#
# GPL
#
#

if(description)
{
 script_version ("$Revision: 1.5 $");
 script_id(11493);
 script_name(english:"Sambar Default Accounts");
 
 
 desc["english"] = "
The Sambar web server comes with some default accounts.

This script makes sure that all these accounts have a password
set.

Solution : Set a password for each account

Risk factor : Medium / High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for default accounts";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

valid = NULL;
hole = 0;

users = make_list("billy-bob", "admin", "anonymous");

foreach user (users)
{
content = "RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr&RCuser=" + user +
"&RCpwd=";


req = string(
"POST /session/login HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: Mozilla/5.0 (Nessus; rv:1.2.1)\r\n",
"Accept: text/xml, text/html\r\n",
"Accept-Language: us\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: ", strlen(content), "\r\n\r\n",
content);


res = http_keepalive_send_recv(port:port, data:req);
if (res == NULL ) exit(0);
#display(res);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string:res))exit(0);


if("Sambar Server Document Manager" >< res)
 {
 valid += user + '\n';
 if(user == "admin")hole ++;
 }
}


if( valid  )
{
 report = '
It is possible to log in as the following passwordless users in the remote 
Sambar web server :

' +
valid +
'

An attacker may use this flaw to alter the content of this server.

Solution : Disable these accounts
Risk factor : ';
 
  if(hole) report += "High";
  else report += "Medium";
  
 if(hole)security_hole(port:port, data:report);
 else security_warning(port:port, data:report);
}
