#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16323);
 script_cve_id("CVE-2005-0343");
 script_bugtraq_id(12471);
 
 script_version ("$Revision: 1.4 $");
 name["english"] = "PerlDesk SQL Injection Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] =  "
The remote host is running PerlDesk, a web-based helpdesk application
written in perl.

The remote version of this software is vulnerable to several SQL
injection vulnerabilities which may allow an attacker to execute
arbitrary SQL statements on the remote SQL database.

Solution : Upgrade to the latest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if PerlDesk is vulnerable to a SQL injection attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_post(item:dir + "/kb.cgi?view='&lang=en", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if("Couldn't execute statement: You have an error in your SQL syntax near ''' at line 1; stopped" >< res )
  {
  security_hole(port);
  exit(0);
  }
}
