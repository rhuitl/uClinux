#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Note that we need to be authenticated for this check
# to work properly.
#


if(description)
{
 script_id(11662);
 script_bugtraq_id(7675);
 script_cve_id("CVE-2000-0188");
 script_version("$Revision: 1.5 $");
 
 name["english"] = "iiprotect sql injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running iisprotect, an IIS add-on to protect the
pages served by this server.

There is a bug in the remote version of iisprotect which may allow
an attacker who has the ability to browse the administrative
interface to execute arbitrary commands through SQL injection
on this host.

Solution : Upgrade to the latest version of IISprotect
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if iisprotect is password-protected";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);


if(get_port_state(port))
{
 req = http_get(item:"/iisprotect/admin/SiteAdmin.ASP?V_SiteName=&V_FirstTab=Groups&V_SecondTab=All&GroupName=nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("Microsoft OLE DB Provider" >< res)exit(0);
 
 req = http_get(item:"/iisprotect/admin/SiteAdmin.ASP?V_SiteName=&V_FirstTab=Groups&V_SecondTab=All&GroupName=nessus'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("Microsoft OLE DB Provider" >< res)security_hole(port);
}
