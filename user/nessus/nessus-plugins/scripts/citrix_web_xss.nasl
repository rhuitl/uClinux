#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
#
# 

if(description)
{
  script_id(12301);
  script_cve_id("CVE-2003-1157");
  script_bugtraq_id(8939);
  if(defined_func("script_xref"))script_xref(name:"OSVDB", value:"2762");
  script_version ("$Revision: 1.4 $");

  name["english"] = "Citrix Web Interface XSS";

  script_name(english:name["english"]);
 
  desc["english"] = "
The remote server is running a Citrix Web Interface server that is vulnerable to cross site scripting.  When a user fails to authenticate, the Citrix Web Interface includes the error message text in the URL.  The error message can be tampered with to perform a XSS attack.  

See also: 
 - http://support.citrix.com/kb/entry.jspa?entryID=3211 (Citrix Document ID: CTX102686)
 - https://www.cert.org/archive/pdf/cross_site_scripting.pdf
 - http://www.security-corporation.com/articles-20031102-001.html

Solution : Upgrade to Citrix Web Interface 2.1 or newer.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Citrix Web Interface Cross Site Scripting Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michael J. Richardson",
		francais:"Ce script est Copyright (C) 2003 Michael J. Richardson");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) 
  exit(0);


function check(url)
  {
    req = http_get(item:string(url, "/login.asp?NFuse_LogoutId=&NFuse_MessageType=Error&NFuse_Message=<SCRIPT>alert('Ritchie')</SCRIPT>&ClientDetection=ON"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if ( res == NULL ) 
      exit(0);

    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<SCRIPT>alert('Ritchie')</SCRIPT>" >< res)
      {
        security_warning(port);
        exit(0);
      }
 
  }

check(url:"/citrix/nfuse/default");
check(url:"/citrix/MetaframeXP/default");
