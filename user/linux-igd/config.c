#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include "globals.h"

#define NMATCH 3

int getConfigOptionArgument(char var[],int varlen, char line[], regmatch_t *submatch) 
{
    /* bound buffer operations to varlen - 1 */
    int match_length = min(submatch[1].rm_eo-submatch[1].rm_so, varlen - 1);

    strncpy(var,&line[submatch[1].rm_so],match_length);
    // Make sure var[] is null terminated
    var[match_length] = '\0';
    return 0;
}

int getConfigOptionDuration(long int *duration,char line[], regmatch_t *submatch) 
{
  long int dur;
  int absolute_time = submatch[1].rm_eo-submatch[1].rm_so; // >0 if @ was present
  char num[NUM_LEN];
  char *p;

  /* bound buffer operations to NUM_LEN - 1 */
  unsigned int len = min(submatch[2].rm_eo-submatch[2].rm_so, NUM_LEN - 1);

  strncpy(num, &line[submatch[2].rm_so], len);
  num[len] = '\0';
  if ((p=index(num,':'))==NULL) {
    dur = atol(num);
  }
  else {
    *p++ = '\0';
    dur = atol(num)*3600 + atol(p)*60;
  }
  if (absolute_time)
    dur *= -1;
  *duration = dur;
  return 0;
}

int parseConfigFile(globals_p vars)
{
    FILE *conf_file;
    regmatch_t submatch[NMATCH]; // Stores the regex submatch start and end index
    
    regex_t re_comment;
    regex_t re_empty_row;
    regex_t re_iptables_location;
    regex_t re_debug_mode;
    regex_t re_insert_forward_rules_yes;
    regex_t re_forward_chain_name;
    regex_t re_prerouting_chain_name;
    regex_t re_upstream_bitrate;
    regex_t re_downstream_bitrate;
    regex_t re_duration;
    regex_t re_desc_doc;
    regex_t re_xml_path;

    // Make sure all vars are 0 or \0 terminated
    vars->debug = 0;
    vars->forwardRules = 0;
    strcpy(vars->iptables,"");
    strcpy(vars->forwardChainName,"");
    strcpy(vars->preroutingChainName,"");
    strcpy(vars->upstreamBitrate,"");
    strcpy(vars->downstreamBitrate,"");
    vars->duration = DEFAULT_DURATION;
    strcpy(vars->descDocName,"");
    strcpy(vars->xmlPath,"");

    // Regexp to match a comment line
    regcomp(&re_comment,"^[[:blank:]]*#",0);
    regcomp(&re_empty_row,"^[[:blank:]]*\r?\n$",REG_EXTENDED);

    // Regexps to match configuration file settings
    regcomp(&re_iptables_location,"iptables_location[[:blank:]]*=[[:blank:]]*\"([^\"]+)\"",REG_EXTENDED);
    regcomp(&re_debug_mode,"debug_mode[[:blank:]]*=[[:blank:]]*([[:digit:]])",REG_EXTENDED);
    regcomp(&re_insert_forward_rules_yes,"insert_forward_rules[[:blank:]]*=[[:blank:]]*yes",REG_ICASE);
    regcomp(&re_forward_chain_name,"forward_chain_name[[:blank:]]*=[[:blank:]]*([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_prerouting_chain_name,"prerouting_chain_name[[:blank:]]*=[[:blank:]]([[:alpha:]_-]+)",REG_EXTENDED);
    regcomp(&re_upstream_bitrate,"upstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_downstream_bitrate,"downstream_bitrate[[:blank:]]*=[[:blank:]]*([[:digit:]]+)",REG_EXTENDED);
    regcomp(&re_duration,"duration[[:blank:]]*=[[:blank:]]*(@?)([[:digit:]]+|[[:digit:]]+{2}:[[:digit:]]+{2})",REG_EXTENDED);
    regcomp(&re_desc_doc,"description_document_name[[:blank:]]*=[[:blank:]]*([[:alpha:].]{1,20})",REG_EXTENDED);
    regcomp(&re_xml_path,"xml_document_path[[:blank:]]*=[[:blank:]]*([[:alpha:]_/.]{1,50})",REG_EXTENDED);

    if ((conf_file=fopen(CONF_FILE,"r")) != NULL)
    {
	char line[MAX_CONFIG_LINE];
	// Walk through the config file line by line
	while(fgets(line,MAX_CONFIG_LINE,conf_file) != NULL)
	{
	    // Check if a comment line or an empty one
	    if ( (0 != regexec(&re_comment,line,0,NULL,0)  )  && 
		 (0 != regexec(&re_empty_row,line,0,NULL,0))  )
	    {
		// Chec if iptables_location
		if (regexec(&re_iptables_location,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->iptables, PATH_LEN, line, submatch);
		}
		
		// Check is insert_forward_rules
		else if (regexec(&re_insert_forward_rules_yes,line,0,NULL,0) == 0)
		{
		    vars->forwardRules = 1;
		}
		// Check forward_chain_name
		else if (regexec(&re_forward_chain_name,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->forwardChainName, CHAIN_NAME_LEN, line, submatch);
		}
		else if (regexec(&re_debug_mode,line,NMATCH,submatch,0) == 0)
		{
		  char tmp[2];
		  getConfigOptionArgument(tmp,sizeof(tmp),line,submatch);
		  vars->debug = atoi(tmp);
		}
		else if (regexec(&re_prerouting_chain_name,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->preroutingChainName, CHAIN_NAME_LEN, line, submatch);
		}
		else if (regexec(&re_upstream_bitrate,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->upstreamBitrate, BITRATE_LEN, line, submatch);
		}
		else if (regexec(&re_downstream_bitrate,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->downstreamBitrate, BITRATE_LEN, line, submatch);
		}
		else if (regexec(&re_duration,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionDuration(&vars->duration,line,submatch);
		}
		else if (regexec(&re_desc_doc,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->descDocName, PATH_LEN, line, submatch);
		}
		else if (regexec(&re_xml_path,line,NMATCH,submatch,0) == 0)
		{
		  getConfigOptionArgument(vars->xmlPath, PATH_LEN, line, submatch);
		}
		else
		{
		    // We end up here if ther is an unknown config directive
		    printf("Unknown config line:%s",line);
		}
	    }
	}
	fclose(conf_file);
    }
    regfree(&re_comment);
    regfree(&re_empty_row);
    regfree(&re_iptables_location);
    regfree(&re_debug_mode);	
    regfree(&re_insert_forward_rules_yes);	
    regfree(&re_forward_chain_name);
    regfree(&re_prerouting_chain_name);
    regfree(&re_upstream_bitrate);
    regfree(&re_downstream_bitrate);
    regfree(&re_duration);
    regfree(&re_desc_doc);
    regfree(&re_xml_path);
    // Set default values for options not found in config file
    if (strnlen(vars->forwardChainName, CHAIN_NAME_LEN) == 0)
    {
	// No forward chain name was set in conf file, set it to default
	snprintf(vars->forwardChainName, CHAIN_NAME_LEN, IPTABLES_DEFAULT_FORWARD_CHAIN);
    }
    if (strnlen(vars->preroutingChainName, CHAIN_NAME_LEN) == 0)
    {
	// No prerouting chain name was set in conf file, set it to default
	snprintf(vars->preroutingChainName, CHAIN_NAME_LEN, IPTABLES_DEFAULT_PREROUTING_CHAIN);
    }
    if (strnlen(vars->upstreamBitrate, BITRATE_LEN) == 0)
    {
	// No upstream_bitrate was found in the conf file, set it to default
	snprintf(vars->upstreamBitrate, BITRATE_LEN, DEFAULT_UPSTREAM_BITRATE);
    }
    if (strnlen(vars->downstreamBitrate, BITRATE_LEN) == 0)
    {
	// No downstream bitrate was found in the conf file, set it to default
	snprintf(vars->downstreamBitrate, BITRATE_LEN, DEFAULT_DOWNSTREAM_BITRATE);
    }
    if (strnlen(vars->descDocName, PATH_LEN) == 0)
    {
	snprintf(vars->descDocName, PATH_LEN, DESC_DOC_DEFAULT);
    }
    if (strnlen(vars->xmlPath, PATH_LEN) == 0)
    {
	snprintf(vars->xmlPath, PATH_LEN, XML_PATH_DEFAULT);
    }
    if (strnlen(vars->iptables, PATH_LEN) == 0) {
	// Can't find the iptables executable, return -1 to 
	// indicate en error
	return -1;
    }
    else
    {
	return 0;
    }
}
