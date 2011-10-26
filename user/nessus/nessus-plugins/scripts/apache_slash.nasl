#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# changes by rd : - script description
#                 - more verbose report
#                 - check for k < 16 in find_index()
#                 - script id
#
# See the Nessus Scripts License for details
#

  desc["english"] = "
Synopsis:

It is possible to obtain the list of the contents of the remote directory.

Description :

Certain versions of Apache for Win32 have a bug wherein remote users
can list directory entries.  Specifically, by appending multiple /'s
to the HTTP GET command, the remote Apache server will list all files
and subdirectories within the web root (as defined in httpd.conf).

Solution : 

Upgrade to the most recent version of Apache at www.apache.org

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
  script_id(10440);
  script_bugtraq_id(1284);
 script_version ("$Revision: 1.30 $");
  script_cve_id("CVE-2000-0505");
  script_name(english:"Check for Apache Multiple / vulnerability");

  script_description(english:desc["english"]);
  script_summary(english:"Send multiple /'s to Windows Apache Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Remote file access");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");



function find_index(k) {

    if(k < 16)k = 17;
    for (q=k-16; q<k; q=q+1) {
            buf = http_get(item:crap(length:q, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if ( incoming == NULL ) exit(0);
            if ("Index of /" >< incoming)  {
		report = desc["english"] + '\n\nPlugin output:\n\nThe contents of / are :\n' + incoming;
                security_warning(port:port, data:report);
                exit(0);
            }
         
    }
    exit(0);
}




port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);

if ( "Apache" >!< banner  ) exit(0);
if ( !thorough_tests && "Win32" >!< banner )  exit(0);



req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( "Index of /" >< res ) exit(0);

if(get_port_state(port)) {
    for (i=2; i < 512; i=i+16) {
            buf = http_get(item:crap(length:i, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if(incoming == NULL)exit(0);
            if ("Forbidden" >< incoming) {
                  find_index(k:i);
            }
        
    }
}
