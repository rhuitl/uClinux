#
# This script written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10995);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-1999-0508");

 name["english"] = "Sun JavaServer Default Admin Password";
 script_name(english:name["english"]);

 desc["english"] = "
This host is running the Sun JavaServer.  This 
server has the default username and password 
of admin.  An attacker can use this to gain 
complete control over the web server 
configuration and possibly execute commands. 

Solution:   Set the web administration interface to require a 
            complex password.  For more information please 
            consult the documentation located in the /system/ 
            directory of the web server.
            
            
Risk factor : High
";

 script_description(english:desc["english"]);

 summary["english"] = "Sun JavaServer Default Admin Password";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 9090);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");


req = "/servlet/admin?category=server&method=listAll&Authorization=Digest+";
req = req + "username%3D%22admin%22%2C+response%3D%22ae9f86d6beaa3f9ecb9a5b7e072a4138%22%2C+";
req = req + "nonce%3D%222b089ba7985a883ab2eddcd3539a6c94%22%2C+realm%3D%22adminRealm%22%2C+";
req = req + "uri%3D%22%2Fservlet%2Fadmin%22&service=";

ports = add_port_in_list(list:get_kb_list("Services/www"), port:9090);

foreach port (ports)
{
    if ( ! get_kb_item("Services/www/" + port + "/embedded") )
    {
    soc = http_open_socket(port);
    if (soc)
    {
        req = string("GET ", req, " HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        if (("server.javawebserver.serviceAdmin" >< buf))
        {
            security_hole(port:port);
        }
    }
  }
}
