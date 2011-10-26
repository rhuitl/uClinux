#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(12096);
 script_cve_id("CVE-2004-1806");
 script_bugtraq_id(9854, 9856);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"4229");
 }
 
 script_version("$Revision: 1.7 $");
 name["english"] = "cfWebStore SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running cfWebStore 5.0.0 or older.

There is a flaw in this software which may allow anyone to inject arbitrary 
SQL statements in the remote database, which may in turn be used to gain 
administrative access on the remote host, read or modify the content of the
remote database.

Solution : Upgrade to cfWebStore 5.0.1 or later.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir)
{
  req = http_get(item:dir + "/index.cfm?fuseaction=category.display&category_ID='", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  #display(buf);
  if ("cfquery name=&quot;request.QRY_GET_CAT&quot;" >< buf )
  	{
	security_hole(port);
	exit(0);
	}
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
