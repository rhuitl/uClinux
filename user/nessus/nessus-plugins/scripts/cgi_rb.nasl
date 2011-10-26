#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Debian security team
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15710);
 script_cve_id("CVE-2004-0983");
 script_bugtraq_id(11618);
 
 script_version ("$Revision: 1.4 $");
 name["english"] = "cgi.rb";
 script_name(english:name["english"]);
 
 desc["english"] = "
The 'cgi.rb' CGI is installed. Some versions is vulnerable to
remote denial of service.

By sending a specially crafted HTTP POST request, a malicious user can force
the remote host to consume a large amount of CPU ressources.

*** Warning : Nessus solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem

Solution : Verify that your version is at least 1.8.1 or later
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of cgi.rb";
 summary["francais"] = "Vérifie la présence de cgi.rb";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"cgi.rb", port:port);
if(res)security_warning(port);
