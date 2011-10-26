#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an information disclosure flaw. 

Description :

The remote host is running Clever Copy, a free web portal written in
PHP. 

The version of Clever Copy installed on the remote host fails to limit
access to the 'admin/connect.inc' include file, which contains
information used by the application to connect to a database.  An
unauthenticated attacker can view the contents of this file using a
simple GET command and use the information to launch other attacks
against the affected host. 

See also :

http://advisories.echo.or.id/adv/adv28-K-159-2006.txt

Solution :

Limit access to Clever Copy's admin directory using, say, a .htaccess
file. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc);

if (description)
{
  script_id(21215);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1718");
  script_bugtraq_id(17461);

  script_name(english:"Clever Copy connect.inc Information Disclosure Vulnerability");
  script_summary(english:"Reads Clever Copy's admin/connect.inc file");

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to read the file.
  req = http_get(item:string(dir, "/admin/connect.inc"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the file.
  if (egrep(pattern:"\$(Host|Dbase|User|Pass)[ \t]*=[ \t]*", string:res))
  {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file 'admin/connect.inc' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
