#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# updated for Westpoint ltd. by Paul Johnston <paul@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

desc = "
Some of the IIS sample files are present.

They all contain various security flaws which could allow 
an attacker to execute arbitrary commands, read arbitrary files 
or gain valuable information about the remote system. 

Solution : Delete the whole /iissamples directory
Reference : http://online.securityfocus.com/infocus/1318
Risk factor : High";

if(description)
{
 script_id(10370);
 script_version ("$Revision: 1.23 $");

 name["english"] = "IIS dangerous sample files";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Determines whether IIS samples files are installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#--
# List of files and text strings to scan for
#--
files[0]    = "/iissamples/issamples/fastq.idq";
messages[0] = "The template file can not be found in the location specified";
 
files[1]    = "/iissamples/issamples/query.idq";
messages[1] = messages[0];
  
files[2]    = "/iissamples/exair/search/search.idq";
messages[2] = messages[0];
 
files[3]    = "/iissamples/exair/search/query.idq";
messages[3] = messages[0];
 
files[4]    = "/iissamples/issamples/oop/qsumrhit.htw?CiWebHitsFile=/iissamples/issamples/oop/qsumrhit.htw&CiRestriction=none&CiHiliteType=Full";
messages[4] = "This is the formatting page for webhits summary highlighting.";
    
files[5]    = "/iissamples/issamples/oop/qfullhit.htw?CiWebHitsFile=/iissamples/issamples/oop/qfullhit.htw&CiRestriction=none&CiHiliteType=Full";
messages[5] = "This is the formatting page for webhits full highlighting";

files[6]    = "/scripts/samples/search/author.idq";
messages[6] = messages[0];

files[7]    = "/scripts/samples/search/filesize.idq";
messages[7] = messages[0];
    
files[8]    = "/scripts/samples/search/filetime.idq";
messages[8] = messages[0];
 
files[9]    = "/scripts/samples/search/queryhit.idq";
messages[9] = messages[0];
 
files[10]    = "/scripts/samples/search/simple.idq";
messages[10] = messages[0];
 
files[11]    = "/iissamples/exair/howitworks/codebrws.asp";
messages[11] = "ASP Source code browser";
    
files[12]    = "/iissamples/issamples/query.asp";
messages[12] = "Sample ASP Search Form";

# these produce false positive against IIS

# files[0]    = "/scripts/samples/search/qfullhit.htw",
# messages[0] = "The format of QUERY_STRING is invalid.");
# files[0]    = "/scripts/samples/search/qsumrhit.htw",
# messages[0] = "The format of QUERY_STRING is invalid.");
        
#--
# Scan for all the files in the list
#--
found_files = "";


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


for(i = 0; files[i]; i = i + 1)
{
      request = http_get(item: files[i], port: port);
      response = http_keepalive_send_recv(port:port, data:request);
      if(response == NULL)break;
      
      if(messages[i] >< response)
      {
        found_files = string(found_files, files[i], "\n");
      }
}

#--
# Report any holes found
#--
if(found_files != "")
{
  msg = string("\n\nThe following files are present:\n\n");
  report = string(desc, msg, found_files);  
  security_hole(data: report, port: port);
}
