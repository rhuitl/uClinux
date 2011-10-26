#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(15453);
 script_cve_id("CVE-2004-2198", "CVE-2004-2199", "CVE-2004-2200", "CVE-2004-2201", "CVE-2004-2202");
 script_bugtraq_id(11363);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10663");
   script_xref(name:"OSVDB", value:"10664");
   script_xref(name:"OSVDB", value:"10665");
   script_xref(name:"OSVDB", value:"10666");
   script_xref(name:"OSVDB", value:"10667");
   script_xref(name:"OSVDB", value:"10668");
   script_xref(name:"OSVDB", value:"10669");
 }
 script_version ("$Revision: 1.4 $");

 script_name(english:"DUware multiple vulnerabilities");
 desc["english"] = "
The remote host is running a product published by DUware - either
DUclassmate, DUclassified or DUforum.

There is a flaw in the remote version of this software which may allow
an attacker to execute arbitrary SQL statements on the remote host by
supplying malformed values to the arguments of /admin/, messages.asp or
messagesDetails.asp.

Solution : Upgrade the newest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if the remote ASP scripts are vulnerable to SQL injection"); 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

urls = make_list("/index.asp?user='", "messageDetail.asp?MSG_ID='");
foreach d (cgi_dirs())
{
 foreach url (urls) 
 {
 req = http_get(item: d + url, port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< res )
  {
  security_hole(port);
  exit(0);
  }
 }
}
