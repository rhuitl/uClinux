#
# (C) Tenable Network Security
#
# Thanks to Cory Scott from @stake for his help during the writing of
# this plugin
#

if(description)
{
 script_id(14847);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11267);
 script_cve_id("CVE-2004-0917");
 
 name["english"] = "Vignette Application Portal Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Vignette Application Portal, a commercially available
portal suite.

There is an information disclosure vulnerability in the remote version
of this software. An attacker can request the diagnostic utility which
will disclose information about the remote site by requesting /portal/diag/.


See also : http://www.atstake.com/research/advisories/2004/a092804-1.txt
Solution : Restrict access to the diag directory
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Request /portal/diag"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs)) dirs = make_list("");
else dirs = make_list(dirs);


foreach dir (dirs)
{
 req = http_get(item:string(dir , "/portal/diag/index.jsp"), port:port);
 res = http_keepalive_send_recv(port:port, data:req); 
 if( res == NULL ) exit(0);
 if("Vignette Application Portal Diagnostic Report" >< res )
 {
  security_warning(port);
 }
}


