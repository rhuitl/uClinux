#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11311);
 script_bugtraq_id(5804);
 script_version ("$Revision: 1.12 $");
 
 script_cve_id("CVE-2002-0692");
 name["english"] = "shtml.exe overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has FrontPage Server Extensions (FPSE) installed.

There is a denial of service / buffer overflow condition
in the program 'shtml.exe' which comes with it. However, 
no public detail has been given regarding this issue yet,
so it's not possible to remotely determine if you are
vulnerable to this flaw or not.

If you are, an attacker may use it to crash your web server
(FPSE 2000) or execute arbitrary code (FPSE 2002). Please
see the Microsoft Security Bulletin MS02-053 to determine
if you are vulnerable or not.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-053.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of shtml.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl", "smb_registry_full_access.nasl", "smb_reg_service_pack_W2K.nasl", "smb_reg_service_pack_XP.nasl", "frontpage_chunked_overflow.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
  req = http_get(item:"/_vti_bin/shtml.exe", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL )exit(0);
  
  if("Smart HTML" >< res){
  req = http_get(item:"/_vti_bin/shtml.exe/nessus.htm", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL )exit(0);
  if ("&quot;nessus.htm&quot;" >!< res ) security_hole ( port ) ;
 }
}

