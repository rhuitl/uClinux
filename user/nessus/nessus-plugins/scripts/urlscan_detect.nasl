#
# (C) Tenable Network Security
#
#
# Ref: 
#  Date: Sat, 31 May 2003 13:58:58 +1200
#  From: Stephen Cope <mail@nonsense.kimihia.org.nz>
#  To: bugtraq@securityfocus.com
#  Subject: URLScan detection


if(description)
{
 script_id(11699);
 script_bugtraq_id(7767);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "URLScan Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is using URLScan to protect itself,
which is a good thing. 

However since it is possible to determine that URLScan is installed, 
an attacker may safely assume that the remote web server is 
Internet Information Server.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the presence of URLScan";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


#
# Method#1 : do a HTTP HEAD on a regular non-existant page and
# a forbidden fruit, and compare the results (if UseFastPathReject
# is disabled, we will identify the remote urlscan server).
# 
soc = http_open_socket(port);
if(!soc)exit(0);
req = http_head(item:"/someunexistantstuff" + rand() + rand() + ".html", port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);
res = tolower(res);
if( "<!doctype" >< res || "<html>" >< res ) exit(0);


req = http_head(item:"/someunexistantstuff.exe", port:port);
soc = http_open_socket(port);
if(!soc)exit(0);
send(socket:soc, data:req);
res2 = http_recv(socket:soc);
close(soc); 
res2 = tolower(res2);

flag = 0;
if( "<!doctype" >< res2 || "<html>" >< res2 ) { flag = 1; }

#
# Method#2 : Compare the results for a HTTP GET for a non-existant
# page and a forbidden page (is UseFastPathReject is set, then we'll
# note several differences). 
# If UseFastPathReject is set, we will receive a very very small error
# message, whereas we will receive a much longer one if it's not
# 
req = http_get(item:"/someunexistantantsutff" + rand() + rand() + ".html", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string:res))exit(0);
if( res == NULL ) exit(0);

req = http_get(item:"/someunexistantantsutff.exe", port:port);
res2 = http_keepalive_send_recv(port:port, data:req);
if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string:res2))exit(0);
if( res2 == NULL ) exit(0);

if(strlen(res) > 2 * strlen(res2) && flag )security_note(port);

