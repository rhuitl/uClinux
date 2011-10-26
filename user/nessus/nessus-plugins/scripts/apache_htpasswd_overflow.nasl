#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  This script is released under the GNU GPL v2
#
# Fixed by Tenable 26-May-2005:
#   - added BIDs 13777 and 13778
#   - extended banner check to cover 1.3.33 as well.
#   - edited description.

if(description)
{
 script_id(14771);
 script_version("$Revision: 1.7 $");

 script_bugtraq_id(13777, 13778);
 
 name["english"] = "Apache <= 1.3.33 htpasswd local overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running Apache 1.3.33 or older.

There is a local buffer overflow in the 'htpasswd' command in these
versions that may allow a local user to gain elevated privileges if
'htpasswd' is run setuid or a remote user to run arbitrary commands
remotely if the script is accessible through a CGI. 

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

See also : http://archives.neohapsis.com/archives/bugtraq/2004-10/0345.html
Solution : Make sure htpasswd does not run setuid and is not accessible
           through any CGI scripts.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Apache <= 1.3.33";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "macosx_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);
 
serv = strstr(banner, "Server:");
if(!serv)exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-9]|3[0-3])))", string:serv))
 {
   security_warning(port);
 } 
}
