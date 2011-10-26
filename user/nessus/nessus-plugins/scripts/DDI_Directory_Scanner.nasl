##
#   This plugin was written by H D Moore <hdm@digitaloffense.net>
##


if(description)
{
	script_id(11032);
	script_version ("$Revision: 1.62 $");
	# script_cve_id("CVE-MAP-NOMATCH");
	# NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
 if (defined_func("script_xref"))
  script_xref(name:"OWASP", value:"OWASP-CM-006");

 
 	name["english"] = "Directory Scanner";
 	script_name(english:name["english"]);
 
	desc["english"] = "
This plugin attempts to determine the presence of various
common dirs on the remote web server";

	script_description(english:desc["english"]);
 	summary["english"] = "Directory Scanner";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_dependencie("find_service.nes", "httpver.nasl", "embedded_web_server_detect.nasl");
	script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
	script_timeout(360);
	exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

num_discovered = 0;


function check_cgi_dir(dir)
{
 local_var req, res;

 req = http_get(item:dir + "/non-existant"  + string(rand()), port:port);
 res = http_keepalive_send_recv(data:req, port:port);
 if(res == NULL)exit(0);
 if(egrep(pattern:"^HTTP.* 404 .*", string:res))
	return 1;
  else
	return 0;
}

function check_req_send(port, url)
{
 soc = http_open_socket(port);
 if(!soc)return(0);
 req = http_get(item:url, port:port);
 send(socket:soc, data:req);
 return(soc);
}


function check_req_recv(soc)
{
 if(soc == 0)
  return(0);
  
 if(fake404 == "BadString0987654321*DDI*")
         http_resp = recv_line(socket:soc, length:255);
    else
    	 http_resp = http_recv(socket:soc);
 http_close_socket(soc);
 return(http_resp);
}


function check_dir_list (dir)
{
    for (CDC=0; dirs[CDC]; CDC=CDC+1)
    {
        if (dirs[CDC] == dir)
        {
            return(1);
        }
    }
    return(0);
}

function check_discovered_list (dir)
{
    for (CDL=0; discovered[CDL]; CDL=CDL+1)
    {
        if (discovered[CDL] == dir)
        {
            return(1);
        }
    }
    return(0);
}

function add_discovered_list (dir)
{
    if (check_discovered_list(dir:dir) == 0)
    {  
        discovered[discovered_last] = dir;
        discovered_last = discovered_last + 1;
	num_discovered ++;
        if ( num_discovered > 50 ) exit(0); # Bogus Server
    }
}

CGI_Dirs = make_list();



dirs[0] = ".cobalt";  score[0] = 1;
dirs[1] = "1";	      
dirs[2] = "10";
dirs[3] = "2";
dirs[4] = "3";
dirs[5] = "4";
dirs[6] = "5";
dirs[7] = "6";
dirs[8] = "7";
dirs[9] = "8";
dirs[10] = "9";
dirs[11] = "AdminWeb"; 		score[11] = 1;
dirs[12] = "Admin_files"; 	score[12] = 1;
dirs[13] = "Administration"; 	score[13] = 1;
dirs[14] = "AdvWebAdmin"; 	score[14] = 1;
dirs[15] = "Agent";
dirs[16] = "Agents";
dirs[17] = "Album";
dirs[18] = "CS";
dirs[19] = "CVS";
dirs[20] = "DMR";
dirs[21] = "DocuColor";
dirs[22] = "GXApp";
dirs[23] = "HB";
dirs[24] = "HBTemplates";
dirs[25] = "IBMWebAS";
dirs[26] = "Install";		score[26] = 1;
dirs[27] = "JBookIt";
dirs[28] = "Log";
dirs[29] = "Mail";		score[29] = 1;
dirs[30] = "Msword";
dirs[31] = "NSearch";
dirs[32] = "NetDynamic";
dirs[33] = "NetDynamics";
dirs[34] = "News";		score[34] = 1;
dirs[35] = "PDG_Cart";		score[35] = 1;
dirs[36] = "README";		score[36] = 1;
dirs[37] = "ROADS";
dirs[38] = "Readme";		score[38] = 1;
dirs[39] = "SilverStream";
dirs[40] = "Stats";		score[40] = 1;
dirs[41] = "StoreDB";		score[41] = 1;
dirs[42] = "Templates";	
dirs[43] = "ToDo";		score[43] = 1;
dirs[44] = "WebBank";
dirs[45] = "WebCalendar";	score[45] = 1;
dirs[46] = "WebDB";
dirs[47] = "WebShop";
dirs[48] = "WebTrend";		score[48] = 1;
dirs[49] = "Web_store";
dirs[50] = "XSL";
dirs[51] = "_ScriptLibrary";
dirs[52] = "_backup";		score[52] = 1;
dirs[53] = "_derived";
dirs[54] = "_errors";		score[54] = 1;
dirs[55] = "_fpclass";
dirs[56] = "_mem_bin";
dirs[57] = "_notes";
dirs[58] = "_objects";
dirs[59] = "_old";
dirs[60] = "_pages";
dirs[61] = "_passwords";	score[61] = 1;
dirs[62] = "_private";		score[62] = 1;
dirs[63] = "_scripts";		score[63] = 1; exec[63] = 1;
dirs[64] = "_sharedtemplates";
dirs[65] = "_tests";		score[65] = 1;
dirs[66] = "_themes";
dirs[67] = "_vti_bin";		score[67] = 1;
dirs[68] = "_vti_bot";		score[68] = 1;
dirs[69] = "_vti_log";		score[69] = 1;
dirs[70] = "_vti_pvt";		score[70] = 1;
dirs[71] = "_vti_shm";		score[71] = 1;
dirs[72] = "_vti_txt";		score[72] = 1;
dirs[73] = "a";
dirs[74] = "acceso";
dirs[75] = "access";		score[75] = 1;
dirs[76] = "accesswatch";
dirs[77] = "acciones";
dirs[78] = "account";		score[78] = 1;
dirs[79] = "accounting";	score[79] = 1;
dirs[80] = "activex";
dirs[81] = "adm";		score[81] = 1;
dirs[82] = "admcgi";
dirs[83] = "admentor";
dirs[84] = "admin";		score[84] = 1;
dirs[85] = "admin-bak";		score[85] = 1;
dirs[86] = "admin-old";		score[86] = 1;
dirs[87] = "admin.back";	score[87] = 1;
dirs[88] = "admin_";		score[88] = 1;
dirs[89] = "administration";	score[89] = 1;
dirs[90] = "administrator";	score[90] = 1;
dirs[91] = "adminuser";		score[91] = 1;
dirs[92] = "adminweb";		score[92] = 1;
dirs[93] = "admisapi";		
dirs[94] = "agentes";
dirs[95] = "analog";		score[95] = 1;
dirs[96] = "anthill";
dirs[97] = "apache";
dirs[98] = "app";
dirs[99] = "applets";
dirs[100] = "application";
dirs[101] = "applications";
dirs[102] = "apps";
dirs[103] = "ar";
dirs[104] = "archive";		score[104] = 1;
dirs[105] = "archives";		score[105] = 1;
dirs[106] = "asp";		score[106] = 1; exec[106] = 1;
dirs[107] = "atc";
dirs[108] = "auth";		score[108] = 1;
dirs[109] = "authadmin";	score[109] = 1;
dirs[110] = "aw";
dirs[111] = "ayuda";
dirs[112] = "b";
dirs[113] = "b2-include";
dirs[114] = "back";
dirs[115] = "backend";
dirs[116] = "backup";		score[116] = 1;
dirs[117] = "backups";		score[117] = 1;
dirs[118] = "bak";		score[118] = 1;
dirs[119] = "banca";
dirs[120] = "banco";
dirs[121] = "bank";
dirs[122] = "banner";
dirs[123] = "banner01";
dirs[124] = "banners";
dirs[125] = "batch";
dirs[126] = "bb-dnbd";
dirs[127] = "bbv";
dirs[128] = "bdata";
dirs[129] = "bdatos";
dirs[130] = "beta";
dirs[131] = "billpay";
dirs[132] = "bin";
dirs[133] = "boadmin";
dirs[134] = "boot";
dirs[135] = "btauxdir";
dirs[136] = "bug";
dirs[137] = "bugs";
dirs[138] = "bugzilla";
dirs[139] = "buy";
dirs[140] = "buynow";
dirs[141] = "c";
dirs[142] = "cache-stats";
dirs[143] = "caja";
dirs[144] = "card";
dirs[145] = "cards";
dirs[146] = "cart";
dirs[147] = "cash";
dirs[148] = "caspsamp";
dirs[149] = "catalog";
dirs[150] = "cbi-bin";		score[150] = 1 ; exec[150] = 1;
dirs[151] = "ccard";		score[151] = 1;
dirs[152] = "ccards";		score[152] = 1;
dirs[153] = "cd";
dirs[154] = "cd-cgi";		score[154] = 1; exec[154]		= 1;
dirs[155] = "cdrom";
dirs[156] = "ce_html";
dirs[157] = "cert";
dirs[158] = "certificado";
dirs[159] = "certificate";
dirs[160] = "cfappman";
dirs[161] = "cfdocs";
dirs[162] = "cfide";		score[162] = 1;	exec[162]	  = 1;
dirs[163] = "cgi";		score[163] = 1; exec[163]	  = 1;
dirs[164] = "cgi-auth";		score[164] = 1; exec[164]	  = 1;
dirs[165] = "cgi-bin";		score[165] = 1; exec[165]	  = 1;
dirs[166] = "cgi-bin2";		score[166] = 1; exec[166]	  = 1;
dirs[167] = "cgi-csc";		score[167] = 1; exec[167]	  = 1;
dirs[168] = "cgi-lib";		score[168] = 1; exec[168]	  = 1;
dirs[169] = "cgi-local";	score[169] = 1; exec[169]	  = 1;
dirs[170] = "cgi-scripts";	score[170] = 1; exec[170]	  = 1;
dirs[171] = "cgi-shl";		score[171] = 1; exec[171]	  = 1;
dirs[172] = "cgi-shop";		score[172] = 1; exec[172]	  = 1;
dirs[173] = "cgi-sys";		score[173] = 1; exec[173]	  = 1;
dirs[174] = "cgi-weddico"; 	score[174] = 1; exec[174]	  = 1;  	  
dirs[175] = "cgi-win";		score[175] = 1; exec[175]	  = 1;
dirs[176] = "cgibin";		score[176] = 1; exec[176]	  = 1;
dirs[177] = "cgilib";		score[177] = 1; exec[177]	  = 1;
dirs[178] = "cgis";		score[178] = 1; exec[178]	  = 1;
dirs[179] = "cgiscripts";	score[179] = 1; exec[179]	  = 1;
dirs[180] = "cgiwin";		score[180] = 1; exec[180]	  = 1;
dirs[181] = "class";		score[181] = 1; exec[181]	  = 1;
dirs[182] = "classes";		score[182] = 1; exec[182]	  = 1;
dirs[183] = "cliente";
dirs[184] = "clientes";
dirs[185] = "cm";
dirs[186] = "cmsample";
dirs[187] = "cobalt-images";
dirs[188] = "code";
dirs[189] = "comments";
dirs[190] = "common";
dirs[191] = "communicator";
dirs[192] = "compra";
dirs[193] = "compras";
dirs[194] = "compressed";
dirs[195] = "conecta";
dirs[196] = "conf";
dirs[197] = "config";		score[197] = 1;
dirs[198] = "connect";
dirs[199] = "console";
dirs[200] = "controlpanel";
dirs[201] = "core";
dirs[202] = "corp";
dirs[203] = "correo";
dirs[204] = "counter";
dirs[205] = "credit";		score[205] = 1;
dirs[206] = "cron";
dirs[207] = "crons";
dirs[208] = "crypto";
dirs[209] = "csr";
dirs[210] = "css";
dirs[211] = "cuenta";
dirs[212] = "cuentas";
dirs[213] = "currency";
dirs[214] = "customers";	score[214] = 1;
dirs[215] = "cvsweb";
dirs[216] = "cybercash";
dirs[217] = "d";
dirs[218] = "darkportal";
dirs[219] = "dat";
dirs[220] = "data";
dirs[221] = "database";		score[221] = 1;
dirs[222] = "databases";	score[222] = 1;
dirs[223] = "datafiles";	score[223] = 1;
dirs[224] = "dato";
dirs[225] = "datos";
dirs[226] = "db";		score[226] = 1;
dirs[227] = "dbase";		score[227] = 1;
dirs[228] = "dcforum";
dirs[229] = "ddreport";
dirs[230] = "ddrint";
dirs[231] = "demo";		score[231] = 1;
dirs[232] = "demoauct";
dirs[233] = "demomall";
dirs[234] = "demos";		score[234] = 1;
dirs[235] = "design";
dirs[236] = "dev";		score[236] = 1;
dirs[237] = "devel";		score[237] = 1;
dirs[238] = "development";
dirs[239] = "dir";
dirs[240] = "directory";	score[240] = 1;
dirs[241] = "directorymanager";
dirs[242] = "dl";
dirs[243] = "dm";
dirs[244] = "dms";
dirs[245] = "dms0";
dirs[246] = "dmsdump";
dirs[247] = "doc";		score[247] = 1;
dirs[248] = "doc-html";
dirs[249] = "doc1";
dirs[250] = "docs";
dirs[251] = "docs1";
dirs[252] = "document";		score[252] = 1;
dirs[253] = "documents";	score[253] = 1;
dirs[254] = "down";
dirs[255] = "download";		score[255] = 1;
dirs[256] = "downloads";	score[256] = 1;
dirs[257] = "dump";
dirs[258] = "durep";
dirs[259] = "e";
dirs[260] = "easylog";
dirs[261] = "eforum";
dirs[262] = "ejemplo";
dirs[263] = "ejemplos";
dirs[264] = "email";	      score[264] = 1;
dirs[265] = "emailclass";
dirs[266] = "employees";
dirs[267] = "empoyees";
dirs[268] = "empris";
dirs[269] = "envia";
dirs[270] = "enviamail";
dirs[271] = "error";
dirs[272] = "errors";
dirs[273] = "es";
dirs[274] = "estmt";
dirs[275] = "etc";
dirs[276] = "example";
dirs[277] = "examples";
dirs[278] = "exc";
dirs[279] = "excel";
dirs[280] = "exchange";
dirs[281] = "exe";
dirs[282] = "exec";
dirs[283] = "export";
dirs[284] = "external";
dirs[285] = "f";
dirs[286] = "fbsd";
dirs[287] = "fcgi-bin";
dirs[288] = "file";
dirs[289] = "filemanager";
dirs[290] = "files";
dirs[291] = "foldoc";
dirs[292] = "form";
dirs[293] = "form-totaller";
dirs[294] = "forms";
dirs[295] = "formsmgr";
dirs[296] = "forum";
dirs[297] = "forums";
dirs[298] = "foto";
dirs[299] = "fotos";
dirs[300] = "fpadmin";
dirs[301] = "fpdb";
dirs[302] = "fpsample";
dirs[303] = "framesets";
dirs[304] = "ftp";
dirs[305] = "ftproot";
dirs[306] = "g";
dirs[307] = "gfx";
dirs[308] = "global";
dirs[309] = "grocery";
dirs[310] = "guest";
dirs[311] = "guestbook";
dirs[312] = "guests";
dirs[313] = "help";
dirs[314] = "helpdesk";
dirs[315] = "hidden";	score[315] = 1;
dirs[316] = "hide";
dirs[317] = "hit_tracker";
dirs[318] = "hitmatic";
dirs[319] = "hlstats";   score[319] = 1;
dirs[320] = "home";
dirs[321] = "hostingcontroller";
dirs[322] = "ht";
dirs[323] = "htbin";  score[323] = 1; exec[323] = 1;
dirs[324] = "htdocs"; score[324] = 1;
dirs[325] = "html";
dirs[326] = "hyperstat";
dirs[327] = "ibank";
dirs[328] = "ibill";
dirs[329] = "icons";
dirs[330] = "idea";
dirs[331] = "ideas";
dirs[332] = "iisadmin"; 	score[332] = 1;
dirs[333] = "iissamples";	score[333] = 1;
dirs[334] = "image";
dirs[335] = "imagenes";
dirs[336] = "imagery";
dirs[337] = "images";
dirs[338] = "img";
dirs[339] = "imp";
dirs[340] = "import";
dirs[341] = "impreso";
dirs[342] = "inc";
dirs[343] = "include";		score[343] = 1;
dirs[344] = "includes";		score[344] = 1;
dirs[345] = "incoming";		score[345] = 1;
dirs[346] = "info";
dirs[347] = "information";
dirs[348] = "ingresa";
dirs[349] = "ingreso";
dirs[350] = "install";
dirs[351] = "internal";
dirs[352] = "intranet";		score[352] = 1;
dirs[353] = "inventory";
dirs[354] = "invitado";
dirs[355] = "isapi";
dirs[356] = "japidoc";
dirs[357] = "java";
dirs[358] = "javascript";
dirs[359] = "javasdk";
dirs[360] = "javatest";
dirs[361] = "jave";
dirs[362] = "jdbc";
dirs[363] = "job";
dirs[364] = "jrun";
dirs[365] = "js";
dirs[366] = "jserv";
dirs[367] = "jslib";
dirs[368] = "jsp";
dirs[369] = "junk";
dirs[370] = "kiva";
dirs[371] = "labs";
dirs[372] = "lcgi";
dirs[373] = "lib";
dirs[374] = "libraries";
dirs[375] = "library";
dirs[376] = "libro";
dirs[377] = "links";
dirs[378] = "linux";
dirs[379] = "loader";
dirs[380] = "log";		score[380] = 1;
dirs[381] = "logfile";
dirs[382] = "logfiles";
dirs[383] = "logg";
dirs[384] = "logger";
dirs[385] = "logging";
dirs[386] = "login";		score[386] = 1;
dirs[387] = "logon";		score[387] = 1;
dirs[388] = "logs";		score[388] = 1;
dirs[389] = "lost+found";	score[389] = 1;
dirs[390] = "mail";
dirs[391] = "mail_log_files";
dirs[392] = "mailman";
dirs[393] = "mailroot";
dirs[394] = "makefile";
dirs[395] = "mall_log_files";
dirs[396] = "manage";
dirs[397] = "manual";
dirs[398] = "marketing";
dirs[399] = "members";
dirs[400] = "message";
dirs[401] = "messaging";
dirs[402] = "metacart";
dirs[403] = "misc";
dirs[404] = "mkstats";
dirs[405] = "movimientos";
dirs[406] = "mqseries";
dirs[407] = "msql";
dirs[408] = "mysql";
dirs[409] = "mysql_admin";	score[409] = 1;
dirs[410] = "ncadmin";
dirs[411] = "nchelp";
dirs[412] = "ncsample";
dirs[413] = "netbasic";
dirs[414] = "netcat";
dirs[415] = "netmagstats";
dirs[416] = "netscape";
dirs[417] = "netshare";
dirs[418] = "nettracker";
dirs[419] = "new";
dirs[420] = "nextgeneration";
dirs[421] = "nl";
dirs[422] = "noticias";
dirs[423] = "objects";
dirs[424] = "odbc";
dirs[425] = "old";		score[425] = 1;
dirs[426] = "old_files";	score[426] = 1;
dirs[427] = "oldfiles";		score[427] = 1;
dirs[428] = "oprocmgr-service";
dirs[429] = "oprocmgr-status";
dirs[430] = "oracle";		score[430] = 1;
dirs[431] = "oradata";
dirs[432] = "order";
dirs[433] = "orders";
dirs[434] = "outgoing";
dirs[435] = "owners";
dirs[436] = "pages";
dirs[437] = "passport";
dirs[438] = "password";		score[438] = 1;
dirs[439] = "passwords";	score[439] = 1;
dirs[440] = "payment";		score[440] = 1;
dirs[441] = "payments";		score[441] = 1;
dirs[442] = "pccsmysqladm";
dirs[443] = "perl";
dirs[444] = "perl5";
dirs[445] = "personal";
dirs[446] = "pforum";
dirs[447] = "phorum";
dirs[448] = "php";
dirs[449] = "phpBB";		exec[449] = 1;
dirs[450] = "phpMyAdmin";	exec[450] = 1;
dirs[451] = "phpPhotoAlbum";	exec[451] = 1;
dirs[452] = "phpSecurePages";	exec[452] = 1;
dirs[453] = "php_classes";	exec[453] = 1;
dirs[454] = "phpclassifieds";	exec[454] = 1;
dirs[455] = "phpimageview";	exec[455] = 1;
dirs[456] = "phpnuke";		exec[456] = 1;
dirs[457] = "phpprojekt";	exec[457] = 1;
dirs[458] = "piranha";	
dirs[459] = "pls";
dirs[460] = "poll";
dirs[461] = "polls";
dirs[462] = "postgres";
dirs[463] = "ppwb";
dirs[464] = "printers";
dirs[465] = "priv";
dirs[466] = "privado";
dirs[467] = "private";		score[467] = 1;
dirs[468] = "prod";
dirs[469] = "protected";	score[469] = 1;
dirs[470] = "prueba";
dirs[471] = "pruebas";
dirs[472] = "prv";
dirs[473] = "pub";
dirs[474] = "public";
dirs[475] = "publica";
dirs[476] = "publicar";
dirs[477] = "publico";
dirs[478] = "publish";
dirs[479] = "purchase";
dirs[480] = "purchases";
dirs[481] = "pw";
dirs[482] = "random_banner";
dirs[483] = "rdp";
dirs[484] = "register";
dirs[485] = "registered";
dirs[486] = "report";
dirs[487] = "reports";
dirs[488] = "reseller";
dirs[489] = "restricted";
dirs[490] = "retail";
dirs[491] = "reviews";
dirs[492] = "root";
dirs[493] = "rsrc";
dirs[494] = "sales";
dirs[495] = "sample";
dirs[496] = "samples";
dirs[497] = "save";
dirs[498] = "script";
dirs[499] = "scripts";			exec[499] = 1;
dirs[500] = "search";
dirs[501] = "search-ui";
dirs[502] = "secret";		score[502] = 1;
dirs[503] = "secure";		score[503] = 1;
dirs[504] = "secured";		score[504] = 1;
dirs[505] = "sell";
dirs[506] = "server-info";
dirs[507] = "server-status";
dirs[508] = "server_stats";
dirs[509] = "servers";
dirs[510] = "serverstats";
dirs[511] = "service";
dirs[512] = "services";
dirs[513] = "servicio";
dirs[514] = "servicios";
dirs[515] = "servlet";
dirs[516] = "servlets";
dirs[517] = "session";
dirs[518] = "setup";
dirs[519] = "share";
dirs[520] = "shared";
dirs[521] = "shell-cgi";
dirs[522] = "shipping";
dirs[523] = "shop";
dirs[524] = "shopper";
dirs[525] = "site";
dirs[526] = "siteadmin";	score[526] = 1;
dirs[527] = "sitemgr";
dirs[528] = "siteminder";
dirs[529] = "siteminderagent";
dirs[530] = "sites";		score[530] = 1;
dirs[531] = "siteserver";
dirs[532] = "sitestats";
dirs[533] = "siteupdate";
dirs[534] = "smreports";
dirs[535] = "smreportsviewer";
dirs[536] = "soap";
dirs[537] = "soapdocs";
dirs[538] = "software";
dirs[539] = "solaris";
dirs[540] = "source";
dirs[541] = "sql";
dirs[542] = "squid";
dirs[543] = "src";
dirs[544] = "srchadm";
dirs[545] = "ssi";		score[545] = 1;
dirs[546] = "ssl";		score[546] = 1;
dirs[547] = "sslkeys";		score[547] = 1;
dirs[548] = "staff";
dirs[549] = "stat";		score[549] = 1;
dirs[550] = "statistic";	score[550] = 1;
dirs[551] = "statistics";	score[551] = 1;
dirs[552] = "stats";		score[552] = 1;
dirs[553] = "stats-bin-p";
dirs[554] = "stats_old";	score[554] = 1;
dirs[555] = "status";
dirs[556] = "storage";
dirs[557] = "store";
dirs[558] = "storemgr";
dirs[559] = "stronghold-info";
dirs[560] = "stronghold-status";
dirs[561] = "stuff";
dirs[562] = "style";
dirs[563] = "styles";
dirs[564] = "stylesheet";
dirs[565] = "stylesheets";
dirs[566] = "subir";
dirs[567] = "sun";
dirs[568] = "super_stats";
dirs[569] = "support";
dirs[570] = "supporter";
dirs[571] = "sys";		score[571] = 1;
dirs[572] = "sysadmin";		score[572] = 1;
dirs[573] = "sysbackup";	score[573] = 1;
dirs[574] = "system";
dirs[575] = "tar";
dirs[576] = "tarjetas";
dirs[577] = "te_html";
dirs[578] = "tech";
dirs[579] = "technote";
dirs[580] = "temp";
dirs[581] = "template";
dirs[582] = "templates";
dirs[583] = "temporal";
dirs[584] = "test";		score[584] = 1;
dirs[585] = "test-cgi";		
dirs[586] = "testing";	 	score[586] = 1;
dirs[587] = "tests";		score[587] = 1;
dirs[588] = "testweb";
dirs[589] = "ticket";
dirs[590] = "tickets";
dirs[591] = "tmp";		score[591] = 1;
dirs[592] = "tools";
dirs[593] = "tpv";
dirs[594] = "trabajo";
dirs[595] = "transito";
dirs[596] = "transpolar";
dirs[597] = "tree";
dirs[598] = "trees";
dirs[599] = "updates";
dirs[600] = "upload";
dirs[601] = "uploads";
dirs[602] = "us";
dirs[603] = "usage";
dirs[604] = "user";
dirs[605] = "userdb";		score[605] = 1;
dirs[606] = "users";		score[606] = 1;
dirs[607] = "usr";
dirs[608] = "ustats";		score[608] = 1;
dirs[609] = "usuario";
dirs[610] = "usuarios";
dirs[611] = "util";
dirs[612] = "utils";
dirs[613] = "vfs";
dirs[614] = "w-agora";
dirs[615] = "w3perl";
dirs[616] = "way-board";
dirs[617] = "web";
dirs[618] = "web800fo";
dirs[619] = "webMathematica";
dirs[620] = "web_usage";	score[620] = 1;
dirs[621] = "webaccess";	score[621] = 1;
dirs[622] = "webadmin";		score[622] = 1;
dirs[623] = "webalizer";	score[623] = 1;
dirs[624] = "webapps";
dirs[625] = "webboard";
dirs[626] = "webcart";
dirs[627] = "webcart-lite";
dirs[628] = "webdata";
dirs[629] = "webdb";
dirs[630] = "webimages";
dirs[631] = "webimages2";
dirs[632] = "weblog";
dirs[633] = "weblogs";
dirs[634] = "webmaster";
dirs[635] = "webmaster_logs";
dirs[636] = "webpub";
dirs[637] = "webpub-ui";
dirs[638] = "webreports";
dirs[639] = "webreps";
dirs[640] = "webshare";
dirs[641] = "website";
dirs[642] = "webstat";		score[642] = 1;
dirs[643] = "webstats";		score[643] = 1;
dirs[644] = "webtrace";
dirs[645] = "webtrends";	score[645] = 1;
dirs[646] = "windows";
dirs[647] = "word";
dirs[648] = "work";
dirs[649] = "wsdocs";
dirs[650] = "wstats";		score[650] = 1;
dirs[651] = "wusage";		score[651] = 1;
dirs[652] = "www";
dirs[653] = "www-sql";
dirs[654] = "wwwjoin";
dirs[655] = "wwwlog";		score[655] = 1;
dirs[656] = "wwwstat";		score[656] = 1;
dirs[657] = "wwwstats";		score[657] = 1;
dirs[658] = "xGB";
dirs[659] = "xml";
dirs[660] = "xtemp";
dirs[661] = "zb41";
dirs[662] = "zipfiles";
dirs[663] = "~1";
dirs[664] = "~admin";		score[664] = 1;
dirs[665] = "~log";
dirs[666] = "~root";
dirs[667] = "~stats";		score[667] = 1;
dirs[668] = "~webstats";	score[668] = 1;
dirs[669] = "~wsdocs";
dirs[670] = "track";
dirs[671] = "tracking";
dirs[672] = "BizTalkTracking";
dirs[673] = "BizTalkServerDocs";
dirs[674] = "BizTalkServerRepository";
dirs[675] = "MessagingManager";
dirs[676] = "iisprotect";
dirs[677] = "mp3";		score[667] = 1;
dirs[678] = "mp3s";		score[668] = 1;
dirs[679] = "acid";
dirs[680] = "chat";
dirs[681] = "eManager";
dirs[682] = "keyserver";
dirs[683] = "search97";
dirs[684] = "tarantella";
dirs[685] = "webmail";
dirs[686] = "flexcube@";
dirs[687] = "flexcubeat";
dirs[688] = "ganglia";
dirs[689] = "sitebuildercontent";
dirs[690] = "sitebuilderfiles";
dirs[691] = "sitebuilderpictures";
dirs[692] = "WSsamples";
dirs[693] = "mercuryboard";
dirs[694] = "tdbin";
dirs[695] = "AlbumArt_";


i = 696;	# max_index(dirs);
# The three following directories exist on Resin default installation
dirs[i++] = "faq";
dirs[i++] = "ref";
dirs[i++] = "cmp";
# Phishing
dirs[i] = "cgi-bim";          exec[i++] = 1; 
# Lite-serve
dirs[i] = "cgi-isapi";		exec[i++] = 1;
# HyperWave
dirs[i++] = "wavemaster.internal";
# Urchin
dirs[i++] = "urchin";
dirs[i++] = "urchin3";
dirs[i++] = "urchin5";
# CVE-2000-0237
dirs[i++] = "publisher";
# Common Locale
dirs[i++] = "en";
dirs[i++] = "en-US";
dirs[i++] = "fr";
dirs[i++] = "intl";
# Seen on Internet
dirs[i++] = "about";
dirs[i++] = "aspx";
dirs[i++] = "Boutiques";
dirs[i++] = "business";
dirs[i++] = "content";
dirs[i++] = "Corporate";
dirs[i++] = "company";
dirs[i++] = "client";
dirs[i++] = "DB4Web";
dirs[i] = "dll";	exec[i++] = 1;
dirs[i++] = "frameset";
dirs[i++] = "howto";
dirs[i++] = "legal";
dirs[i++] = "member";
dirs[i++] = "myaccount";
dirs[i++] = "obj";
dirs[i++] = "offers";
dirs[i++] = "personal_pages";
dirs[i++] = "rem";
dirs[i++] = "Remote";
dirs[i++] = "serve";
dirs[i++] = "shopping";
dirs[i++] = "slide";
dirs[i++] = "solutions";
dirs[i++] = "v4";
dirs[i++] = "wws";		# Sympa
dirs[i++] = "squirrelmail";
dirs[i++] = "dspam";
dirs[i++] = "cacti";

# Add domain name parts
hn = get_host_name();
if (! ereg(string: hn, pattern: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"))
{
 hnp = split(hn, sep: ".");
 foreach p (hnp)
 {
   n = max_index(dirs);
   for (j = 0; j < n && dirs[j] != p; j ++)
     ;
   if (j < n) dirs[n] = p;
 }
}

# this needs to be updated to match the above list
dirs_last = i-1;

# these are the strings used by the 404 checks
errmsg[0] = "not found";
errmsg[1] = "404";
errmsg[2] = "error has occurred";
errmsg[3] = "FireWall-1 message";
errmsg[4] = "Reload acp_userinfo database";
errmsg[5] = "IMail Server Web Messaging";
errmsg[6] = "HP Web JetAdmin";
errmsg[7] = "Error processing SSI file";
errmsg[8] = "ExtendNet DX Configuration";
errmsg[9] = "Unable to complete your request due to added security features";
errmsg[10] = "Client Authentication Remote Service</font>";
errmsg[11] = "Error - Bad Request";
errmsg[12] = "Webmin server";
errmsg[13] = "unknown";
errmsg[14] = "Management Console";
errmsg[15] = "Insufficient Access";
errmsg[16] = "TYPE=password";
errmsg[17] = "The userid or password that was specified is not valid";
errmsg[18] = "Content-Length: 0";

debug = 0;

if(debug) display("\n::[ DDI Directory Scanner running in debug mode\n::\n");

report = string("The following directories were discovered:\n");

found = 0;

authreport = string("The following directories require authentication:\n");

authfound = 0;

fake404 = string("");
Check200 = 1;
Check401 = 1;
Check403 = 1;

# this array contains the results
discovered[0] = 0;
discovered_last = 0;

port = get_http_port(default:80);

if(!port || !get_port_state(port))
{
    if(debug) display(":: Error: port ", port, " was not open on target.\n");
    exit(0);
}



if ( get_kb_item("Services/www/" + port + "/embedded") && ! thorough_tests ) exit(0);

##
# pull the robots.txt file
##



if(debug)display(":: Checking for robots.txt...\n");
req = http_get(item:"/robots.txt", port:port);
http_data = http_keepalive_send_recv(port:port, data:req);

if (ereg(pattern:"^HTTP/1.[01] 200 ", string:http_data))
{
    strings = split(http_data);
    foreach string (strings)
    {
        if (   egrep(pattern:"disallow:.*/", string:string, icase:TRUE) &&
             ! egrep(pattern:"disallow:.*\.", string:string, icase:TRUE)
           )
        {
            # yes, i suck at regex's in nasl. I want my \s+!
            robot_dir = ereg_replace(pattern:"disallow:\W*/(.*)$", string:string, replace:"\1", icase:TRUE); 
            robot_dir = ereg_replace(pattern:"\W*$", string:robot_dir, replace:"", icase:TRUE); 
            robot_dir = ereg_replace(pattern:"/$|\?$", string:robot_dir, replace:"", icase:TRUE); 
            
            if (!check_dir_list(dir:robot_dir))
            {
                # add directory to the list
                dirs_last = dirs_last + 1;
                dirs[dirs_last] = robot_dir;
                if (debug) display(":: Directory '", robot_dir, "' added to test list\n");
            } else {
                if (debug) display(":: Directory '", robot_dir, "' already exists in test list\n");
            }
        }
    }
}


##
# pull the CVS/Entries file
##

if(debug)display(":: Checking for /CVS/Entries...\n");
req = http_get(item:"/CVS/Entries", port:port);
http_data = http_keepalive_send_recv(port:port, data:req);
if(http_data == NULL)exit(0);

if (ereg(pattern:"^HTTP/1.[01] 200 ", string:http_data))
{
    strings = split(http_data, string("\n"));
    
    foreach string (strings)
    {
        if (ereg(pattern:"^D/(.*)////", string:string, icase:TRUE))
        {
            cvs_dir = ereg_replace(pattern:"D/(.*)////.*", string:string, replace:"\1", icase:TRUE); 
            if (! check_dir_list(dir:cvs_dir))
            {
                # add directory to the list
                dirs_last = dirs_last + 1;
                dirs[dirs_last] = cvs_dir;
                if (debug) display(":: Directory '", cvs_dir, "' added to test list\n");
            } else {
                if (debug) display(":: Directory '", cvs_dir, "' already exists in test list\n");
            }
        }
    }
}


##
# test for servers which return 200/403/401 for everything
##

req = http_get(item:"/NonExistant" + rand() + "/", port:port);
http_resp = http_keepalive_send_recv(port:port, data:req);
if(http_resp == NULL)exit(0);


if(ereg(pattern:"^HTTP/1.[01] 200 ", string: http_resp))
{
    fake404 = 0;
    
    if(debug) display(":: This server returns 200 for non-existent directories.\n");
    for(i=0;errmsg[i];i=i+1)
    {
        if (egrep(pattern:errmsg[i], string:http_resp, icase:TRUE) && !fake404)
        {
            fake404 = errmsg[i];
            if(debug) display(":: Using '", fake404, "' as an indication of a 404 error\n");
        }
    }
    
    if (!fake404)
    {
        if(debug) display(":: Could not find an error string to match against for the fake 404 response.\n");
        if(debug) display(":: Checks which rely on 200 responses are being disabled\n");
        Check200 = 0;
    }
} else {
    fake404 = string("BadString0987654321*DDI*");
}

if(ereg(pattern:"^HTTP/1.[01] 401 ", string: http_resp))
{
    if(debug) display(":: This server requires authentication for non-existent directories, disabling 401 checks.\n");
    Check401 = 0;
}

if(ereg(pattern:"^HTTP/1.[01] 403 ", string: http_resp))
{
    if(debug) display(":: This server returns a 403 for non-existent directories, disabling 403 checks.\n");
    Check403 = 0;
}



##
# start the actual directory scan
##

keep_scanning = 1;
ScanRootDir = "/";
max_recurse = 5;



# copy the directory test list
cdirs[0] = 0;
for (dcp=0; dirs[dcp] ; dcp=dcp+1)
{
    cdirs[dcp] = dirs[dcp];
    cdirs_last = dcp;
}


for ( pass = 0 ; pass < 2 ; pass ++ )
{

    start_pass = unixtime();
    if(debug)display(":: Starting the directory scan...\n");
    for(i=0;cdirs[i] ;i = i + 1 )
    {   
	if ( pass == 0 && score[i] == 0 ) continue;
	if ( pass == 1 && score[i] != 0 ) continue;
	res = http_keepalive_send_recv(port:port, data:http_get(item:string(ScanRootDir, cdirs[i], "/"), port:port));
	if ( res == NULL ) exit(0);
	http_code = int(substr(res, 9, 11));

	
	if(!res)res = "BogusBogusBogus";
       

        if( Check200 && 
            http_code == 200 &&
            ! (egrep(pattern:fake404, string:res, icase:TRUE))
          )
        {
            if(debug) display(":: Discovered: " , ScanRootDir, cdirs[i], "\n");

            add_discovered_list(dir:string(ScanRootDir, cdirs[i]));
	    if(exec[i] != 0){
			if(check_cgi_dir(dir:cdirs[i])) CGI_Dirs = make_list(CGI_Dirs, cdirs[i]);
			}
	    
            if(found != 0)
            {
                report = report + ", " + ScanRootDir + cdirs[i];
            } else {
                report = report + ScanRootDir + cdirs[i];
            }
            found=found+1;
        }

        if(Check403 && http_code == 403 )
        {

            if (debug) display(":: Got a 403 for ", ScanRootDir, cdirs[i], ", checking for file in the directory...\n");

            soc = check_req_send(port:port, url:string(ScanRootDir, cdirs[i], "/NonExistent.html"));
	    res2 = check_req_recv(soc:soc);
	    
            if(ereg(pattern:"^HTTP/1.[01] 403 ", string:res2))
            {
                # the whole directory appears to be protected 
                if (debug) display("::   403 applies to the entire directory \n");   
            } else {
                if (debug) display("::   403 applies to just directory indexes \n");

                # the directory just has indexes turned off
                if(debug) display(":: Discovered: " , ScanRootDir, cdirs[i], "\n");
                add_discovered_list(dir:string(ScanRootDir, cdirs[i]));
		if(exec[i] != 0)CGI_Dirs = make_list(CGI_Dirs, cdirs[i]);
		
		
                if(found != 0)
                {
                    report = report + ", " + ScanRootDir + cdirs[i];
                } else {
                    report = report + ScanRootDir + cdirs[i];
                }
                found=found+1;            
            }
        }

        if(Check401 && http_code == 401 )
        {

            if (debug) display(":: Got a 401 for ", ScanRootDir + cdirs[i], "\n");
            if(authfound != 0)
            {
                authreport = authreport + ", " + ScanRootDir + cdirs[i];
            } else {
                authreport = authreport + ScanRootDir + cdirs[i];
            }
	    num_discovered ++;
            if ( num_discovered > 50 ) exit(0); # Bogus Server
            authfound=authfound+1;            
        }    
    }
 if ( pass == 0 && unixtime() - start_pass > 80 && ! thorough_tests ) break; 
}






##
# reporting happens here
##

result = string("");

if (found)
{
    result = report;
    result += string("

While this is not, in and of itself, a bug, you should manually inspect 
these directories to ensure that they are in compliance with company
security standards\n");
}

if (authfound)
{
    result = result + string("\n", authreport);
}

if (strlen(result))
{
    security_note(port:port, data:result);
    for (idx=0; idx < discovered_last; idx=idx+1)
    {
        dir_key = string("www/", port, "/content/directories");
        if(debug) display("Setting KB key: ", dir_key, " to '", discovered[idx], "'\n");
        set_kb_item(name:dir_key, value:discovered[idx]);
    }
}



foreach d (CGI_Dirs)
{
 cgi = cgi_dirs();
 flag = 0;
 foreach c (cgi)
 {
  if(c == "/" + d) {
  	flag = 1;
	break;
	}
 }
 
 if(flag == 0)set_kb_item(name:"/tmp/cgibin", value:"/" + d);
}
