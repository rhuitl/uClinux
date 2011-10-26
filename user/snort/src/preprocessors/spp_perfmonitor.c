/* $Id$ 
**
**  spp_perfmonitor.c
**
**  Copyright (C) 2002 Sourcefire, Inc.
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  6.4.02 - Initial Source Code.  Norton/Roelker
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#include <stdlib.h>
#include <ctype.h>
#include "plugbase.h"
#include "mstring.h"
#include "util.h"
#include "debug.h"
#include "parser.h"

#include "snort.h"
#include "perf.h"

#include "profiler.h"

/*
*  Protype these forward references, and don't clutter up the name space
*/
static void PerfMonitorInit(u_char *args);
static void ParsePerfMonitorArgs(char *args);
static void ProcessPerfMonitor(Packet *p, void *);
void PerfMonitorCleanExit(int, void *);
void PerfMonitorRestart(int, void *);

#ifdef PERF_PROFILING
PreprocStats perfmonStats;
#endif

/*
 * Function: SetupPerfMonitor()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupPerfMonitor()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("PerfMonitor", PerfMonitorInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: PerfMonitor is setup...\n"););
}

/*
 * Function: PerfMonitorInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void PerfMonitorInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: PerfMonitor Initialized\n"););

    /* parse the argument list from the rules file */
    ParsePerfMonitorArgs((char*)args);

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(ProcessPerfMonitor, PRIORITY_SCANNER, PP_PERFMONITOR);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("perfmon", &perfmonStats, 0, &totalPerfStats);
#endif
}

/*
   Perf file -  specified on the command line 
*/
static char perf_file[1025]={""};
void SetPerfmonitorFile( char * s )
{
   if( strlen(s) < sizeof(perf_file)-1 )
   {
      SnortStrncpy(perf_file, s, sizeof(perf_file));
   }
}

/*
 * Function: ParsePerfMonitorArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 *
 *  perfmonitor: [ time 10 flow ]
 *
 * Returns: void function
 *
 */
static void ParsePerfMonitorArgs( char *args)
{
    char **Tokens=NULL;
    int   iTokenNum=0;
    int   i, iTime=60, iFlow=0, iFlowMaxPort=1023, iEvents=0, iMaxPerfStats=0;
    int   iFile=0, iSnortFile=0, iConsole=0, iPkts=10000, iReset=0;
    int   iStatsExit=0;
    char  file[1025];
    char  snortfile[1025];
    int   iRet;
    char  *pcEnd;

    if( args )
    {
       Tokens = mSplit(args, " \t", 50, &iTokenNum, '\\');
    }
    
    for( i = 0; i < iTokenNum; i++ )
    {
        /* Check for a 'time number' parameter */
        if( strcmp( Tokens[i],"time")==0 )
        {
            /* make sure we have at least one more argument */
            if( i == (iTokenNum-1) )
            {
                FatalError("%s(%d) => Missing Time.  The value must be a "
                           "positive integer number.\n", file_name, file_line);
            }

            iTime = strtol(Tokens[++i], &pcEnd, 10);
            if(iTime <= 0 || *pcEnd)
                FatalError("%s(%d) => Invalid Time.  The value must be a "
                           "positive integer number.\n", file_name, file_line);
        }
        else if( strcmp( Tokens[i],"flow-ports")==0 )
        {
              i++;
              if( (i< iTokenNum) && Tokens[i] )
                  iFlowMaxPort= atoi(Tokens[i]);
              
              if( iFlowMaxPort > SF_MAX_PORT )
                  iFlowMaxPort = SF_MAX_PORT;

              iFlow=1;
        }
        else if( strcmp( Tokens[i],"flow")==0 )
        {
            /*
            **  This parameter turns on the flow statistics.
            **  Flow statistics give you the traffic profile
            **  that snort is processing.  This helps in
            **  troubleshooting and performance tuning.
            */
            iFlow = 1;
        }       
        else if( strcmp( Tokens[i],"accumulate")==0)
        {
            iReset=0;
        }
        else if( strcmp( Tokens[i],"reset")==0 )
        {
            iReset=1;
        }
        else if( strcmp( Tokens[i],"events")==0 )
        {
            /*
            **  The events paramenter gives the total number
            **  of qualified and non-qualified events during
            **  the processing sample time.  This allows 
            **  performance problems to be seen in a general
            **  manner.
            */
            iEvents = 1;
        }
        else if(!strcmp(Tokens[i], "max"))
        {
            iMaxPerfStats = 1;
        }
        else if(!strcmp(Tokens[i], "console"))
        {
            iConsole = 1;
        }
        else if(!strcmp(Tokens[i], "file"))
        {
            if( i == (iTokenNum-1) )
            {
                FatalError("%s(%d) => Missing 'file' argument.  This value "
                           "is the file that save stats.\n", 
                           file_name, file_line);
            }

            iFile = 1;
            
            strncpy( file, Tokens[++i], sizeof(file)-1 );
            file[sizeof(file)-1] = 0x00;
        }
        else if(!strcmp(Tokens[i], "snortfile"))
        {
            if( i == (iTokenNum-1) )
            {
                FatalError("%s(%d) => Missing 'snortfile' argument.  This "
                           "value is the file that save stats.\n", 
                           file_name, file_line);
            }

            iSnortFile = 1;

            if(pv.log_dir[strlen(pv.log_dir)-1] == '/')
            {
                iRet = snprintf(snortfile, sizeof(snortfile),
                                "%s%s", pv.log_dir, Tokens[++i]);
            }
            else
            {
                iRet = snprintf(snortfile, sizeof(snortfile),
                                "%s/%s", pv.log_dir, Tokens[++i]);
            }

            if(iRet < 0)
            {
                FatalError("%s(%d) => 'snortfile' argument path is too long.\n",
                           file_name, file_line);
            }
        }
        else if(!strcmp(Tokens[i], "pktcnt"))
        {
            if( i == (iTokenNum-1) )
            {
                FatalError("%s(%d) => Missing 'pktcnt' argument.  This value "
                           "should be a positive integer or zero.\n", 
                           file_name, file_line);
            }

            iPkts = atoi(Tokens[++i]);
            if( iPkts < 0 )
                iPkts = 1000;
        }
        else if (!strcmp(Tokens[i], "atexitonly"))
        {
            iStatsExit = 1;
        }
        else
        {
            FatalError("%s(%d)=> Invalid parameter '%s' to preprocessor"
                       " PerfMonitor.\n", file_name, file_line, Tokens[i]);
        }
    }

    mSplitFree(&Tokens, iTokenNum);

    /*
    *  Initialize the performance system and set flags
    */
    sfInitPerformanceStatistics(&sfPerf);
     
    sfSetPerformanceSampleTime( &sfPerf, iTime );

    sfSetPerformanceStatistics( &sfPerf, SFPERF_BASE );
    
    sfSetPerformanceAccounting( &sfPerf, iReset );
    
    if( iFlow  )
    {
        sfSetPerformanceStatistics( &sfPerf, SFPERF_FLOW );
        sfPerf.sfFlow.maxPortToTrack = iFlowMaxPort;
    }
    
    if( iEvents) sfSetPerformanceStatistics( &sfPerf, SFPERF_EVENT );

    if( iMaxPerfStats ) sfSetPerformanceStatistics(&sfPerf, SFPERF_BASE_MAX);
     
    if( iConsole ) sfSetPerformanceStatistics( &sfPerf, SFPERF_CONSOLE );

    if( iFile && iSnortFile )
    {
        FatalError("%s(%d)=> Cannot log to both 'file' and 'snortfile'.\n",
                   file_name, file_line);
    }
    
    if( iFile || iSnortFile || strlen(perf_file) ) 
    {
        /* use command line override if applicable */
        if( strlen(perf_file) )
        {
            iFile=1;
            if( sfSetPerformanceStatisticsEx( &sfPerf, SFPERF_FILE, perf_file ) )
            {
                FatalError("Cannot open performance log file '%s'\n",perf_file);
            }
        }
        else
        {
            if(iFile)
            {
                if( sfSetPerformanceStatisticsEx( &sfPerf, SFPERF_FILE, file ) )
                {
                    FatalError("Cannot open performance log file '%s'\n",file);
                }
            }
            else if(iSnortFile)
            {
                if( sfSetPerformanceStatisticsEx(&sfPerf, SFPERF_FILE, snortfile) )
                {
                    FatalError("Cannot open performance log file '%s'\n",snortfile);
                }
            }
        }
    }
    
    if( iPkts) sfSetPerformanceStatisticsEx( &sfPerf, SFPERF_PKTCNT, &iPkts );
    if( iStatsExit) sfSetPerformanceStatisticsEx( &sfPerf, SFPERF_SUMMARY, &iStatsExit );

    LogMessage("PerfMonitor config:\n");
    LogMessage("    Time:           %d seconds\n", iTime);
    LogMessage("    Flow Stats:     %s\n", iFlow ? "ACTIVE" : "INACTIVE");
    LogMessage("    Event Stats:    %s\n", iEvents ? "ACTIVE" : "INACTIVE");
    LogMessage("    Max Perf Stats: %s\n", 
            iMaxPerfStats ? "ACTIVE" : "INACTIVE");
    LogMessage("    Console Mode:   %s\n", iConsole ? "ACTIVE" : "INACTIVE");
    LogMessage("    File Mode:      %s\n", 
            iFile ? file : "INACTIVE");
    LogMessage("    SnortFile Mode: %s\n", 
            iSnortFile ? snortfile : "INACTIVE");
    LogMessage("    Packet Count:   %d\n", iPkts);
    LogMessage("    Dump Summary:   %s\n", sfPerf.iPerfFlags & SFPERF_SUMMARY ?
        "Yes" : "No");

    AddFuncToPreprocCleanExitList(PerfMonitorCleanExit, NULL, PRIORITY_LAST, PP_PERFMONITOR);
    AddFuncToPreprocRestartList(PerfMonitorRestart, NULL, PRIORITY_LAST, PP_PERFMONITOR);

    if (sfPerf.iPerfFlags & SFPERF_SUMMARY)
    {
        CheckSampleInterval(time(NULL), &sfPerf);
    }
   
    return;
}


/*
 * Function: ProcessPerfMonitor(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
static void ProcessPerfMonitor(Packet *p, void *context)
{
    static  int first=1;
    PROFILE_VARS;

    if( first )
    {
        extern pcap_t * pd;
        struct pcap_stat pcapStats;
        pcap_stats(pd,&pcapStats);
        first=0;
        sfPerf.sfBase.pkt_stats.pkts_recv = pcapStats.ps_recv;
        sfPerf.sfBase.pkt_stats.pkts_drop = pcapStats.ps_drop;
    }

    if(p == NULL) 
    {
        return;
    }


    PREPROC_PROFILE_START(perfmonStats);
    /*
    *  Performance Statistics  
    */
    if (pv.rotate_perf_file)
    {
        sfRotatePerformanceStatisticsFile(&sfPerf);
        pv.rotate_perf_file = 0;
    }

    if(sfPerf.sample_interval > 0)
    {
        if(p->pkth)
        {
            sfPerformanceStats(&sfPerf, p->pkt, p->pkth->caplen, 
                               p->packet_flags & PKT_REBUILT_STREAM);
        }
    }
    
    if( p->tcph )
    {
        if((p->tcph->th_flags & TH_SYN) && !(p->tcph->th_flags & TH_ACK))
        {
            /* changed to measure syns */
            sfPerf.sfBase.iSyns++;
        }
        else if((p->tcph->th_flags & TH_SYN) && (p->tcph->th_flags & TH_ACK ))
        {
            /* this is a better approximation of connections */
            sfPerf.sfBase.iSynAcks++;
        }
    }

    /*
    *  TCP Flow Perf
    */
    if(p->pkth && (sfPerf.iPerfFlags & SFPERF_FLOW))
   {
        /*
        **  TCP Flow Stats
        */
        if( p->tcph )
        {
            UpdateTCPFlowStatsEx(p->sp, p->dp, p->pkth->caplen);
        }
        /*
        *  UDP Flow Stats
        */
        else if( p->udph )
            UpdateUDPFlowStatsEx(p->sp, p->dp, p->pkth->caplen);

        /*
        *  Get stats for ICMP packets
        */
        else if( p->icmph )
            UpdateICMPFlowStatsEx(p->icmph->type, p->pkth->caplen);
    }

    PREPROC_PROFILE_END(perfmonStats);
    return;
}

/**
 * CleanExit func required by preprocessors
 */
void PerfMonitorCleanExit(int signal, void *foo)
{
    if (sfPerf.iPerfFlags & SFPERF_SUMMARY)
    {
        sfProcessPerfStats(&sfPerf);
    }

    /* Close the performance stats file */
    sfSetPerformanceStatisticsEx(&sfPerf, SFPERF_FILECLOSE, NULL);

    return;
}

/**
 * Restart func required by preprocessors
 */
void PerfMonitorRestart(int signal, void *foo)
{
    /* Close the performance stats file */
    sfSetPerformanceStatisticsEx(&sfPerf, SFPERF_FILECLOSE, NULL);

    return;
}

