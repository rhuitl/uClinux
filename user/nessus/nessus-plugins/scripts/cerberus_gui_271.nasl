#
# (C) Tenable Network Security
#


if (description) {
  script_id(20348);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-4427", "CVE-2005-4428");
  script_bugtraq_id(16062);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:" 21988");
    script_xref(name:"OSVDB", value:" 21989");
    script_xref(name:"OSVDB", value:" 21990");
    script_xref(name:"OSVDB", value:" 21991");
    script_xref(name:"OSVDB", value:" 21992");
    script_xref(name:"OSVDB", value:" 21993");
    script_xref(name:"OSVDB", value:" 21994");
    script_xref(name:"OSVDB", value:" 21995");
  }

  script_name(english:"Cerberus Helpdesk GUI Agent < 2.7.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Cerberus Helpdesk GUI Agent < 2.7.1");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple SQL injection and cross-site scripting flaws. 

Description :

The remote host is running Cerberus Helpdesk, a web-based helpdesk
suite written in PHP. 

The installed version of Cerberus Helpdesk is affected by several SQL
injection issues and one cross-site scripting flaw because of its
failure to sanitize user-supplied input to various parameters and
scripts before using it in database queries and in dynamically-
generated HTML.  Successful exploitation of these issues requires that
an attacker first authenticate. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040324.html
http://forum.cerberusweb.com/showthread.php?s=&postid=30315

Solution : 

Upgrade to Cerberus GUI Agent version 2.7.1 when it becomes available. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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
if (thorough_tests) dirs = make_list("/cerberus", "/cerberus-gui", "/helpdesk", "/tickets", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get the login page.
  req = http_get(item:string(dir, "/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Exploitation requires authentication so the best we can do is a banner check.
  if (egrep(pattern:'class="cer_footer_text">Cerberus Helpdesk .+ Version ([01]\\..+|2\\.([0-6]\\..*|7\\.0)) Release<br>', string:res)) {
    security_warning(port);
    exit(0);
  }
}
