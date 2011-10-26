#
# (C) Tenable Network Security
#
desc = "The remote host is running Hosting Controller a web hosting management
application.

The remote version of this software is vulnerable to an information disclosure
flaw which may allow an attacker to gather additional data on the remote host.

An attacker may download the file $path/logs/HCDiskQuotaService.csv and
gain the list of hosted domains.

Solution : Block access to the file $path/logs/HCDiskQuoteService.csv
Risk factor : Low";

if(description)
{
 script_id(17308);
 script_bugtraq_id(12748);
 script_version("$Revision: 1.4 $");
 name["english"] = "Hosting Controller Multiple Information Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Downloads HCDiskQuoteService.csv";
 
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

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  req = http_get(item:dir + "/logs/HCDiskQuotaService.csv", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if ("Date,Time,Action,Comments," >< buf )
  	{
	desc = str_replace(find:"$path", replace:dir, string:desc);
	security_note(port:port, data:desc);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
foreach dir (cgi_dirs()) check( dir : dir );
