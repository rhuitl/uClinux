#
# This script was written by Nate Haggard (SecurityMetrics inc.)
#
# See the Nessus Scripts License for details
#
#
# changes by rd: pattern matching to determine if the file is CVS indeed
#

if(description)
{
 script_id(10922);
 script_version ("$Revision: 1.12 $");

 name["english"] = "CVS/Entries";
 script_name(english:name["english"]);
 
 desc["english"] = "
Your website allows read access to the CVS/Entries file.  
This exposes all file names in your CVS module on your website.  
Change your website permissions to deny access to your CVS 
directory. 

Risk factor : Medium";


 script_description(english:desc["english"]);
 summary["english"] = "requests CVS/Entries";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Nate Haggard (SecurityMetrics inc.)");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404") ) exit(0);

res = is_cgi_installed_ka(item:"/CVS/Entries", port:port);
# is_cgi_installed_ka takes care of servers that always return 200
# This was tested with nessus 1.2.1 
if(res)
{
 if (debug_level) display("cvs_in_www.nasl: ", res, "\n");

 soc = http_open_socket(port);
 file = string("/CVS/Entries");
 req = http_get(item:file, port:port);
 send(socket:soc, data:req);
 h = http_recv_headers2(socket:soc);
 r = http_recv_body(socket:soc, headers:h, length:0);
 http_close_socket(soc);

 warning = string("Your website allows read access to the CVS/Entries file.\n");
 warning += string("This exposes all file names in your CVS module on your website.\n\n");
 warning += string("Solution: Change your website permissions to deny access to your\n");
 warning += string("CVS directory.  Entries contains the following: \n", r);

  security_warning(port:port, data:warning);
}
exit(0);
