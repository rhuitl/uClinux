#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11688);
 script_bugtraq_id(7147);
 script_version ("$Revision: 1.11 $");
 name["english"] = "WF-Chat User Account Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is prone
to information disclosure.

Description :

The WF-Chat allows an attacker to view information about registered
users by requesting the files '!nicks.txt' and '!pwds.txt'. 

See also :

http://lists.insecure.org/lists/bugtraq/2003/Mar/0271.html

Solution : 

Delete this CGI.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of !pwds.txt";
 summary["francais"] = "Vérifie la présence de !pwds.txt";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}
#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);

dirs = make_list("/chat", cgi_dirs());
foreach dir (dirs)
{
 req = http_get(item:dir + "/!pwds.txt", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( res == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res))
 {
  idx = stridx(res, string("\r\n\r\n"));
  if ( idx < 0 ) exit(0);
  data = substr(res, idx, strlen(res) - 1);
  notme = egrep(pattern:"^[^ ].*$", string:data);
  if(notme == NULL ){
   req = http_get(item:dir + "/chatlog.txt", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if(res == NULL ) exit(0);
   if(egrep(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .[0-9].*", string:res))
   {
   security_note(port);
   exit(0);
   }
  }
 }
}
