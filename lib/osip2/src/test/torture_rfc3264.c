/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <osipparser2/osip_rfc3264.h>
#include <osipparser2/osip_port.h>

#define AUDIO_CODEC 0x01
#define VIDEO_CODEC 0x02
#define T38_CODEC   0x04
#define APP_CODEC   0x08

int test_add_codec(struct osip_rfc3264 *cnf, int codec_type,
		   int payload, char *attribute);
sdp_message_t *get_test_remote_message(int index, FILE *torture_file, int verbose);

int test_add_codec(struct osip_rfc3264 *cnf, int codec_type,
		   int payload, char *attribute)
{
  sdp_media_t *med;
  sdp_attribute_t *attr;
  char *tmp;
  int i;
  if (payload>127) return -1;
  if (attribute==NULL || strlen(attribute)==0) return -1;

  i = sdp_media_init(&med);
  if (i!=0) goto error;
  
  tmp = malloc(4);
  snprintf(tmp, 3, "%i", payload);
  med->m_proto = strdup("RTP/AVP");
  osip_list_add(med->m_payloads, tmp, -1);

  i = sdp_attribute_init (&attr);
  if (i != 0)
    return -1;
  attr->a_att_field = strdup("rtpmap");
  attr->a_att_value = strdup(attribute);
  osip_list_add (med->a_attributes, attr, -1);


  switch(codec_type)
    {
    case AUDIO_CODEC:
      med->m_media = strdup("audio");
      osip_rfc3264_add_audio_media(cnf, med, -1);
      break;
    case VIDEO_CODEC:
      med->m_media = strdup("video");
      osip_rfc3264_add_video_media(cnf, med, -1);
      break;
    }

  return 0;

 error:
  return -1;
}

sdp_message_t *get_test_remote_message(int index, FILE *torture_file, int verbose)
{
  sdp_message_t *remote_sdp;
  char *msg;
  char *tmpmsg;
  char *tmp;
  char *marker;
  int i;

  i = 0;
  tmp = (char *) osip_malloc (500);
  marker = fgets (tmp, 500, torture_file);	/* lines are under 500 */
  while (marker != NULL && i < index)
    {
      if (0 == strncmp (tmp, "|", 1))
	i++;
      marker = fgets (tmp, 500, torture_file);
    }

  msg = (char *) osip_malloc (10000);	/* msg are under 10000 */
  tmpmsg = msg;

  if (marker == NULL)
    {
      fprintf (stderr,
	       "Error! The message's number you specified does not exist\n");
      osip_free (msg);
      return NULL;			/* end of file detected! */
    }
  /* this part reads an entire message, separator is "|" */
  /* (it is unlinkely that it will appear in messages!) */
  while (marker != NULL && strncmp (tmp, "|", 1))
    {
      osip_strncpy (tmpmsg, tmp, strlen (tmp));
      tmpmsg = tmpmsg + strlen (tmp);
      marker = fgets (tmp, 500, torture_file);
    }

  if (verbose)
      fprintf (stdout, "%s\n", msg);

  i = sdp_message_init(&remote_sdp);
  if (i!=0) return NULL;
  
  i = sdp_message_parse(remote_sdp, msg);
  if (i!=0) return NULL;
  
  return remote_sdp;
}

int main(int argc, char **argv)
{
  struct osip_rfc3264 *cnf;
  int i;
  int verbose = 0;		/* 0: verbose, 1 (or nothing: not verbose) */
  FILE *torture_file;

  if (argc > 3)
    {
      if (0 == strncmp (argv[3], "-v", 2))
	verbose = 1;
      if (0 == strcmp (argv[3], "-vv"))
	verbose = 2;
    }

  fprintf (stdout, "test %i : ============================ \n", atoi(argv[2]));

  torture_file = fopen (argv[1], "r");
  if (torture_file == NULL)
    {
      fprintf (stderr,
	       "Failed to open \"torture_sdps\" file.\nUsage: %s torture_file [-v]\n",
	       argv[0]);
      fprintf (stdout, "test %s : ============================ FAILED\n", argv[2]);
      exit (1);
    }






  i = osip_rfc3264_init(&cnf);
  if (i!=0)
    {
      fprintf(stderr, "Cannot Initialize Negotiator feature.\n");
      osip_rfc3264_free(cnf);
      fclose (torture_file);
      fprintf (stdout, "test %s : ============================ FAILED\n", argv[2]);
      return -1;
    }

  test_add_codec(cnf, AUDIO_CODEC, 0,  "0 PCMU/8000");
  test_add_codec(cnf, AUDIO_CODEC, 8,  "8 PCMA/8000");
  test_add_codec(cnf, AUDIO_CODEC, 18, "18 G729/8000");

  test_add_codec(cnf, VIDEO_CODEC, 97, "97 XXX/11111");
  test_add_codec(cnf, VIDEO_CODEC, 31, "31 H261/90000");

#if 0
  osip_rfc3264_del_video_media(cnf, 0);
  osip_rfc3264_del_audio_media(cnf, 1);
  osip_rfc3264_del_audio_media(cnf, 2);

  test_add_codec(cnf, AUDIO_CODEC, 8,  "0 PCMA/8000");
  test_add_codec(cnf, AUDIO_CODEC, 18, "18 G729/8000");
#endif

  if (verbose==2)
    __osip_rfc3264_print_codecs(cnf);

  {
    sdp_message_t *remote_sdp;
    sdp_media_t *audio_tab[10];
    sdp_media_t *video_tab[10];
    sdp_media_t *t38_tab[10];
    sdp_media_t *app_tab[10];
    int res_audio = 0;
    int res_video = 0;
    int res_t38   = 0;
    int res_app   = 0;

    char str_local_sdp[8192];
    sdp_message_t *local_sdp;
    int mline;
    char *tmp = NULL;

    remote_sdp = get_test_remote_message(atoi(argv[2]), torture_file, verbose);
    if (!remote_sdp)
      {
	fprintf(stderr, "Cannot Get remote SDP message for testing.\n");
	osip_rfc3264_free(cnf);
	fclose (torture_file);
	fprintf (stdout, "test %s : ============================ FAILED\n", argv[2]);
	return -1;
      }

    i=osip_rfc3264_prepare_answer(cnf, remote_sdp, str_local_sdp, 8192);
    if (i!=0)
      {
	fprintf(stderr, "Cannot Prepare local SDP answer from offer.\n");
	osip_rfc3264_free(cnf);
	fclose (torture_file);
	fprintf (stdout, "test %s : ============================ FAILED\n", argv[2]);
	return -1;
      }
    sdp_message_init(&local_sdp);
    i=sdp_message_parse(local_sdp, str_local_sdp);
    if (i!=0)
      {
	fprintf(stderr, "Cannot Parse uncomplete SDP answer from offer.\n");
	sdp_message_free(local_sdp);
	osip_rfc3264_free(cnf);
	fclose (torture_file);
	fprintf (stdout, "test %s : ============================ FAILED\n", argv[2]);
	return -1;
      }

    mline=0;
    while (0==osip_rfc3264_match(cnf, remote_sdp,
				 audio_tab, video_tab, t38_tab, app_tab, mline))
      {
	int pos;

	if (audio_tab[0]==NULL && video_tab[0]==NULL && t38_tab[0]==NULL && app_tab[0]==NULL)
	  {
	    if (verbose)
	      fprintf(stdout, "The remote SDP does not match any local payloads.\n");
	  }
	else
	  {
	    for (pos=0;audio_tab[pos]!=NULL;pos++)
	      {
		int pos2 = 0;
		sdp_media_t *med = audio_tab[pos];
		char *str = (char *) osip_list_get (med->m_payloads, 0);
		if (verbose==2)
		  fprintf(stdout, "\tm=%s %s %s %s\n",
			  med->m_media,
			  med->m_port,
			  med->m_proto,
			  str);
		while (!osip_list_eol (med->a_attributes, pos2))
		  {
		    sdp_attribute_t *attr =
		      (sdp_attribute_t *) osip_list_get (med->a_attributes, pos2);
		    if (verbose==2)
		      fprintf(stdout, "\ta=%s:%s\n",
			      attr->a_att_field,
			      attr->a_att_value);
		    pos2++;
		  }
		if (verbose==2)
		  fprintf(stdout, "\n");

		i=osip_rfc3264_complete_answer(cnf, remote_sdp, local_sdp, audio_tab[pos], mline);
		if (i!=0)
		  {
		    if (verbose)
		      fprintf(stdout, "Error Adding support for codec in answer?\n");
		  }
		else
		  {
		    if (verbose==2)
		      fprintf(stdout, "support for codec added in answer:\n");
		  }
	      }
	    
	    for (pos=0;video_tab[pos]!=NULL;pos++)
	      {
		int pos2 = 0;
		sdp_media_t *med = video_tab[pos];
		char *str = (char *) osip_list_get (med->m_payloads, 0);
		if (verbose==2)
		  fprintf(stdout, "\tm=%s %s %s %s\n",
			  med->m_media,
			  med->m_port,
			  med->m_proto,
			  str);
		while (!osip_list_eol (med->a_attributes, pos2))
		  {
		    sdp_attribute_t *attr =
		      (sdp_attribute_t *) osip_list_get (med->a_attributes, pos2);
		    if (verbose==2)
		      fprintf(stdout, "\ta=%s:%s\n",
			      attr->a_att_field,
			      attr->a_att_value);
		    pos2++;
		  }
		if (verbose==2)
		  fprintf(stdout, "\n");

		i=osip_rfc3264_complete_answer(cnf, remote_sdp, local_sdp, video_tab[pos], mline);
		if (i!=0)
		  {
		    if (verbose)
		      fprintf(stdout, "Error Adding support for codec in answer?\n");
		  }
		else
		  {
		    if (verbose==2)
		      fprintf(stdout, "support for codec added in answer:\n");
		  }
	      }	    
	  }

	mline++;
      }

    if (verbose)
      fprintf(stdout, "Result in answer:\n");
    sdp_message_to_str(local_sdp, &tmp);
    if (tmp!=NULL)
      {
	if (verbose)
	  fprintf(stdout, "\n%s\n", tmp);
	free(tmp);
      }
    else
      {
	if (verbose)
	  fprintf(stdout, "ERROR\n"); 
      }
  }

  osip_rfc3264_free(cnf);
  fclose (torture_file);
  fprintf (stdout, "test %s : ============================ OK\n", argv[2]);
  return 0;
}
