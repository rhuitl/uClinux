#
# This script is (C) Tenable Network Security
#


if(description)
{
 script_id(17209);
 script_cve_id("CVE-2005-0526", "CVE-2005-0630", "CVE-2005-0631");
 script_bugtraq_id(12631, 12633, 12666, 12690, 12694);
 if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14083");
    script_xref(name:"OSVDB", value:"14084");
    script_xref(name:"OSVDB", value:"14085");
 }

 script_version ("$Revision: 1.8 $");
 name["english"] = "PBLang BBS <= 4.65 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws. 

Description :

According to its banner, the remote host is running a version of
PBLang BBS, a bulletin board system written in PHP, that suffers from
the following vulnerabilities:

  - HTML Injection Vulnerability in pmpshow.php.
    An attacker can inject arbitrary HTML and script into the
    body of PMs sent to users allowing for theft of 
    authentication cookies or misrepresentation of the site.

  - Cross-Site Scripting Vulnerability in search.php.
    If an attacker can trick a user into following a specially
    crafted link to search.php from an affected version of
    PBLang, he can inject arbitrary script into the user's 
    browser to, say, steal authentication cookies.

  - Remote PHP Script Injection Vulnerability in ucp.php.
    PBLang allows a user to enter a PHP script into his/her 
    profile values, to be executed with the permissions of
    the web server user whenever the user logs in. 

  - Directory Traversal Vulnerability in sendpm.php.
    A logged-in user can read arbitrary files, subject to
    permissions of the web server user, by passing full
    pathnames through the 'orig' parameter when calling
    sendpm.php.

  - Arbitrary Personal Message Deletion Vulnerability in delpm.php.
    A logged-in user can delete anyone's personal messages by
    passing a PM id through the 'id' parameter and a username 
    through the 'a' parameter when calling delpm.php.

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-02/0406.html
http://archives.neohapsis.com/archives/bugtraq/2005-02/0407.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0015.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0019.html
http://www.nessus.org/u?a6808b6a

Solution : 

Upgrade to PBLang 4.66z or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for multiple vulnerabilities in PBLang BBS <= 4.65";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005-2006 Tenable Network Security");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
  res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/index.php", port:port));
  if ( res == NULL ) exit(0);
  if ( 
    "PBLang Project" >< res && 
    egrep(pattern:'<meta name="description" content=".+running with PBLang ([0-3]\\.|4\\.[0-5]|4\\.6[0-5])">', string:res)
  ) { 
    security_note(port);
    exit(0); 
  }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
