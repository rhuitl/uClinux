#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17996);
 script_bugtraq_id(13002);
 script_version("$Revision: 1.2 $");
 name["english"] = "ProfitCode PayProCart Cross-Site Scripting Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PayProCart, a shopping cart software written
in PHP.

The remote version of this software contains an input validation flaw
in the file 'usrdetails.php' which may allow an attacker to use the remote
host to perform a cross site scripting attack.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks PayProCart";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (make_list( cgi_dirs()))
{
 req = http_get(item:dir + "/usrdetails.php?sgnuptype=csaleID<script>nessus</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if('<input type="hidden" name="sgnuptype" value="csaleID<script>nessus</script>' >< res )
  {
   security_warning(port);
   exit(0);
  }
}
