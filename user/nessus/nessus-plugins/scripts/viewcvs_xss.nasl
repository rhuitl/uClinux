#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: office <office@office.ac>
#
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(14823);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"6458");
 script_bugtraq_id(4818);
 script_cve_id("CVE-2002-0771");
 name["english"] = "ViewCVS XSS";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.7 $"); 
 desc["english"] = "
The remote host seems to be running ViewCVS, an open source CGI written in 
python designed to access CVS directories using a web interface.

The remote version of this software is vulnerable to many cross-site scripting 
flaws though the script 'viewcvs'.

Using a specially crafted URL, an attacker can cause arbitrary code execution 
for third party users, thus resulting in a loss of integrity of their system.

Solution : Update to the latest version of this software
See also: http://viewcvs.sourceforge.net/
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of ViewCVS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(url)
{
  req = http_get(item:string(url, "/viewcvs.cgi/?cvsroot=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);

  if ('The CVS root "<script>foo</script>" is unknown' >< r)
  {
    security_warning(port);
    exit(0);
  }
}


foreach dir (cgi_dirs())
{
 check(url:dir);
}
