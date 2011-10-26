#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17990);
 script_cve_id("CVE-2005-1032");
 script_bugtraq_id(13044);
 script_version("$Revision: 1.5 $");
 name["english"] = "LiteCommerce SQL Injection Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running LiteCommerce, a shopping cart software written
in PHP.

The remote version of this software is vulnerable to various SQL injections
attacks which may let an attacker execute arbitrary SQL statements against
the remote database.

Solution : Upgrade to the newest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks LiteCommerce";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
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
 req = http_get(item:dir + "/cart.php?target=category&category_id=42'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if('SELECT category_id,image_width,image_height,name,description,meta_tags,enabled,views_stats,order_by,membership,threshold_bestsellers,parent,image_type FROM ' >< res )
  {
   security_hole(port);
   exit(0);
  }
}
