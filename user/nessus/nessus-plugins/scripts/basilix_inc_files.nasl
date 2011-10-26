#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10601);
 script_bugtraq_id(2198);
 script_cve_id("CVE-2001-1044");
 script_version ("$Revision: 1.15 $");
 
 name["english"] = "Basilix includes download";
 name["francais"] = "Basilix includes download";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
information disclosure. 

Description :

It is possible to download the include files on the remote BasiliX
webmail service.  An attacker may use these to obtain the MySQL
authentication credentials. 

See also : 

http://www.securityoffice.net/articles/basilix/index.php

Solution :  

Put a handler in your web server for the .inc and .class files.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of include files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach file (make_list("/inc/sendmail.inc", "class/mysql.class")) {
    req = http_get(item:string(dir, file), port:port);
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(r == NULL)exit(0);
  
    if("BasiliX" >< r)
     {
      if("This program is free software" >< r) 
       {
        security_warning(port);
        exit(0);
       }
     }
  }
}
