#
# (C) Tenable Network Security
#
# 
#
# Ref: 
#  Date: 18 Jun 2003 16:33:36 -0000
#  Message-ID: <20030618163336.11333.qmail@www.securityfocus.com>
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com  
#  Subject: phpMyAdmin XSS Vulnerabilities, Transversal Directory Attack ,
#   Information Encoding Weakness and Path Disclosures
#

if(description)
{
 script_id(11761);
 script_bugtraq_id(7962, 7963, 7964, 7965);
 script_version ("$Revision: 1.13 $");
 name["english"] = "phpMyAdmin multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running a version of phpMyAdmin which is vulnerable to 
several flaws :

 - It may be tricked into disclosing the physical path of the remote PHP
   installation.
   
 - It is vulnerable to cross-site scripting, which may allow an attacker
   to steal the cookies of your users.
   
 - It is vulnerable to a flaw which may allow an attacker to list the
   contents of arbitrary directories on the remote server.

An attacker may use these flaws to gain more knowledge about the remote
host and therefore set up more complex attacks against it.

See also :

http://www.securityfocus.com/archive/1/325641
http://www.securityfocus.com/archive/1/327511

Solution : 

Upgrade to phpMyAdmin 2.5.2 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:string(dir, "/db_details_importdocsql.php?submit_show=true&do=import&docpath=../../../../../../../../../../etc"),
 		port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( r == NULL ) exit(0);
  if("Ignoring file passwd" >< r)
  {
    security_note(port);
    exit(0);
  }
}
