#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15829);
 script_cve_id("CVE-2004-1426", "CVE-2004-1427", "CVE-2004-1543");
 script_bugtraq_id(11744, 12132);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "KorWeblog Remote Directory Listing Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using KorWeblog, a web based log application
written in PHP.

A vulnerability exists in the remote version of this product which may allow
a remote attacker to disclose directory listings. Information disclosures
could help the attacker in further attacks.

Solution : Upgrade to KorWeblog 1.6.2 or later.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote KorWeblog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if (ereg(pattern:"Powered by <A HREF=.*KorWeblog 1\.([0-5]\..*|6\.[0-1][^0-9].*)/A>", string:r))
   {
    security_warning(port);
    exit(0);
   }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

