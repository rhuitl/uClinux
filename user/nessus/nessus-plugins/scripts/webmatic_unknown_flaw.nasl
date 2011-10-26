#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14382);
 script_bugtraq_id(11045);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "WebMatic Security Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application that is prone to an
unknown vulnerability. 

Description :

The remote host is running WebMatic, a web-based application designed
to generate websites. 

The vendor has released WebMatic 1.9 to address an unknown flaw in
earlier versions of the software. 

Solution : 

Upgrade to WebMatic 1.9 or later.

Risk factor: 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebMatic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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


foreach dir ( cgi_dirs() )
{
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if ( res == NULL ) exit(0);

 #<a href="http://www.webmatic.tk" TARGET="NEW">Powered by: Webmatic 1.9</a></div></td>
 if ( "Webmatic" >< res && 
      egrep(pattern:"<a href=[^>]+>Powered by: Webmatic (0\.|1\.[0-8][^0-9])", string:res) )
	{
	security_warning( port );
	exit(0);
 	}
}
