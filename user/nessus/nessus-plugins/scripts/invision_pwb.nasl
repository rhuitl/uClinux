#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Alexander Antipov <Antipov SecurityLab ru>
#
#  This script is released under the GNU GPL v2
#

if(description) 
{ 
  script_id(15425); 
  script_version("$Revision: 1.6 $"); 

  script_cve_id("CVE-2004-1578");
  script_bugtraq_id(11332);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"10512");
      
  name["english"] = "Invision Power Board Referer field XSS"; 
        
  script_name(english:name["english"]); 

desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
cross-site scripting issue. 

Description :

This version of Invision Power Board installed on the remote host is
vulnerable to cross-site scripting attacks, which may allow an attacker
to steal a user's cookies. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2004-10/0100.html
        
Solution: 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
        
  script_description(english:desc["english"]); 
        
  summary["english"] = "Checks for Invision Power Board XSS";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
	
  script_dependencies("invision_power_board_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);
if(!can_host_php(port:port))exit(0);
if (get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  s = string( "GET ", dir, "/index.php?s=5875d919a790a7c429c955e4d65b5d54&act=Login&CODE=00 HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n", "Referer: <script>foo</script>", "\r\n\r\n");
  soc =  http_open_socket(port);
  if(!soc) exit(0);

  send(socket: soc, data: s);
  r = http_recv(socket: soc);
  http_close_socket(soc);

  if (egrep(pattern:"input type=.*name=.referer.*<script>foo</script>", string:r) )
    security_warning(port);
}
