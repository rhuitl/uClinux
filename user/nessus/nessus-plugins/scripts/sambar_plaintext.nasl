#
# This script was written by Renaud Deraison
#
#
#

if(description)
{
 script_version ("$Revision: 1.4 $");
#script_cve_id("CVE-MAP-NOMATCH");
 script_id(11585);
 script_name(english:"Sambar Transmits Passwords in PlainText");
 
 
 desc["english"] = "
The remote Sambar server allows user to log in without using SSL.

An attacker with a sniffer on the way between a user's host and
this server may use this flaw to capture the password of the 
users of this server.

With the password, he could then be able to access the webmail
accounts and modify the webpages on behalf of its victim.

Solution : Use Sambar on top of SSL
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Makes sure that Sambar runs on top of SSL";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
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

user = "whatever";
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
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&
   "SAMBAR" >< res)
   {
    transport = get_port_transport(port);
    if(transport == ENCAPS_IP)security_warning(port);
   }
