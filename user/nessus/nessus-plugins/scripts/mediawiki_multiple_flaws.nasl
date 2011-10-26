#
# (C) Tenable Network Security
#


if(description) {
 script_id(18035);
 script_version("$Revision: 1.5 $");

 script_cve_id(
   "CVE-2004-1405",
   "CVE-2004-2185",
   "CVE-2004-2186",
   "CVE-2004-2187"
 );
 if ( NASL_LEVEL >= 2200 )script_bugtraq_id(12625, 12444, 12305, 11985, 11897, 11480, 11416, 11302, 10958, 9057);
 
 script_name(english:"MediaWiki Multiple Remote Vulnerabilities");
 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
multiple flaws, including arbitrary code execution. 

Description :

The remote host appears to be running a version of MediaWiki before
1.3.11.  Such versions suffer from various vulnerabilities, including
some that may allow an attacker to execute arbitrary PHP code on the
remote host.

See also : 

http://sourceforge.net/project/shownotes.php?release_id=307067

Solution: 

Upgrade to MediaWiki 1.3.11 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Test for the version of MedaWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencies("mediawiki_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|10))") {
    security_note(port);
    exit(0);
  }
}
