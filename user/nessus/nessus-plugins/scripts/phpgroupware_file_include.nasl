#
# (C) Tenable Network Security
#
# Ref: 
# Date: 22 Jul 2003 15:05:29 -0000
# From: phil dunn <z3hp@yahoo.com>
# To: bugtraq@securityfocus.com
# Subject: sorry, wrong file


if(description)
{
 script_id(11799);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2006-0524");
 script_bugtraq_id(8241, 16426);
 script_xref(name:"OSVDB", value:"22934");

 name["english"] = "Ashnews Code Injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

It is possible to make the remote host include php files hosted on a
third party server using Ashnews. 

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server. 

In addition, the application reportedly fails to sanitize the 'id'
parameter before using it in dynamically-generated output, subjecting
users to cross-site scripting attacks. 

See also :

http://www.securityfocus.com/archive/1/329910
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041844.html

Solution : 

Remove the software as it is no longer supported.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of ashnews.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
if(!can_host_php(port:port))exit(0);


# Loop through CGI directories.
foreach loc (cgi_dirs()) {
  req = http_get(item:string(loc, "/ashnews.php?pathtoashnews=http://xxxxxxxx/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  if(egrep(pattern:".*http://xxxxxxxx/ashprojects/newsconfig\.php", string:r))
   	security_note(port);
}
