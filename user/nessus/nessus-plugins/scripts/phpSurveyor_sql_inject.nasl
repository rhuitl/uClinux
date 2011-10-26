#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: taqua
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(20376);
 script_version ("$Revision: 1.3 $");

 script_cve_id("CVE-2005-4586");
 script_bugtraq_id(16077);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"22039");
  
 name["english"] = "PHPSurveyor sid SQL Injection Flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description:

The remote host is running PHPSurveyor, a set of PHP scripts that
interact with MySQL to develop surveys, publish surveys and collect
responses to surveys. 

The remote version of this software is prone to a SQL injection flaw. 
Using specially crafted requests, an attacker can manipulate database
queries on the remote system. 

See also :

http://www.phpsurveyor.org/mantis/view.php?id=286
http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605

Solution :

Upgrade to PHPSurveyor version 0.991 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PHPSurveyor sid SQL injection flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# the code
#

 include("global_settings.inc");
 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!get_port_state(port))exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 if (thorough_tests) dirs = make_list("/phpsurveyor", "/survey", cgi_dirs());
 else dirs = make_list(cgi_dirs());

 foreach dir (dirs)
 { 
  req = http_get(item:string(dir,"/admin/admin.php?sid=0'"),port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php", string:r))
  {
    security_warning(port);
    exit(0);
  }
 }
