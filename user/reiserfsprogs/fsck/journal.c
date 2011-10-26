/*
 * Copyright 2000 Hans Reiser
 */

#include "fsck.h"
#include <limits.h>
/*#include <stdlib.h>*/





#define bh_desc(bh) ((struct reiserfs_journal_desc *)((bh)->b_data))
#define bh_commit(bh) ((struct reiserfs_journal_commit *)((bh)->b_data))







static int next_expected_desc (struct super_block * s, struct buffer_head * d_bh)
{
    int offset;
    struct reiserfs_journal_desc * desc;

    desc = (struct reiserfs_journal_desc *)d_bh->b_data;
    offset = d_bh->b_blocknr - SB_JOURNAL_BLOCK (s);
    return SB_JOURNAL_BLOCK (s) + ((offset + desc->j_len + 1 + 1) % JOURNAL_BLOCK_COUNT);
}


static int is_valid_transaction (struct super_block * s, struct buffer_head * d_bh)
{
    struct buffer_head * c_bh;
    int offset;
    struct reiserfs_journal_desc *desc  = (struct reiserfs_journal_desc *)d_bh->b_data;
    struct reiserfs_journal_commit *commit ;
    __u32 block, start_block;


    offset = d_bh->b_blocknr - SB_JOURNAL_BLOCK (s);
    
    /* ok, we have a journal description block, lets see if the transaction was valid */
    block = next_expected_desc (s, d_bh) - 1;
    start_block  = d_bh->b_blocknr;
    while(!(c_bh = bread (s->s_dev, block, s->s_blocksize))){
        if (++block == SB_JOURNAL_BLOCK (s) + JOURNAL_BLOCK_COUNT)
            block = SB_JOURNAL_BLOCK (s);
        if (block == start_block)
            return 0;
    }

    commit = (struct reiserfs_journal_commit *)c_bh->b_data ;
    if (does_desc_match_commit (desc, commit)) {
      //    if (journal_compare_desc_commit (s, desc, commit)) {
/*	printf ("desc and commit block do not match\n");*/
	brelse (c_bh) ;
	return 0;
    }
    brelse (c_bh);
    return 1;
}


int reiserfs_replay_journal (struct super_block * s)
{
    struct buffer_head * d_bh, * c_bh, * jh_bh;
    struct reiserfs_journal_header * j_head;
    struct reiserfs_journal_desc * j_desc;
    struct reiserfs_journal_commit * j_commit;
    unsigned long latest_mount_id;
    unsigned long j_cur;
    unsigned long j_start;
    unsigned long j_size;
    unsigned long mount_id, trans_id;
    unsigned long t_first, t_last, t_count, t_flushed;
    unsigned long t_offset;
    int i;

    fsck_progress ("Analyzing journal..");

    j_start = SB_JOURNAL_BLOCK (s);
    j_cur = 0;
    j_size = rs_journal_size (s->s_rs);
    t_first = 0;
    t_last = 0;
    latest_mount_id = 0;

    /* look for the transactions with the most recent mount_id */
    for (j_cur = 0; j_cur < j_size; ) {
	d_bh = bread (s->s_dev, j_start + j_cur, s->s_blocksize);
	if (d_bh && who_is_this (d_bh->b_data, d_bh->b_size) == THE_JDESC && is_valid_transaction (s, d_bh)) {
	    j_desc = (struct reiserfs_journal_desc *)d_bh->b_data;

	    mount_id = le32_to_cpu (j_desc->j_mount_id);
	    trans_id = le32_to_cpu (j_desc->j_trans_id);

	    if (mount_id > latest_mount_id) {
		/* more recent mount_id found */
		latest_mount_id = mount_id;
		t_first = t_last = trans_id;
		t_offset = j_cur;
		t_count = 1;
	    } else if (mount_id == latest_mount_id) {
		t_count ++;
		if (trans_id > t_last)
		    t_last = trans_id;
		if (trans_id < t_first) {
		    t_first = trans_id;
		    t_offset = j_cur;
		}
	    }
	    j_cur += le32_to_cpu (j_desc->j_len) + 1;
	}
	j_cur ++;
	brelse (d_bh);
    }

    /* replay only if journal header looks resonable */
    jh_bh = bread (s->s_dev, j_start + j_size, s->s_blocksize);
    j_head = (struct reiserfs_journal_header *)(jh_bh->b_data);

    if (latest_mount_id != le32_to_cpu (j_head->j_mount_id)) {
	fsck_progress ("nothing to replay (no transactions match to latest mount id)\n");
	brelse (jh_bh);
	return 0;
    }
    /* last transaction flushed - which should not be replayed */
    t_flushed = le32_to_cpu (j_head->j_last_flush_trans_id);
    if (t_flushed >= t_last) {
	fsck_progress ("nothing to replay (no transactions older than last flushed one found)\n");
	brelse (jh_bh);
	return 0;
    }
    if (t_first > t_flushed + 1) {
	if (t_flushed)
	    fsck_progress ("last flushed trans %lu, the oldest but newer is %lu\n",
			   t_flushed, t_first);
    } else {
	/* start replaying with first not flushed transaction */
	t_first = t_flushed + 1;
	t_offset = le32_to_cpu (j_head->j_first_unflushed_offset);
    }

    fsck_progress ("last flushed trans %lu, mount_id %lu, "
		   "will replay from %lu up to %lu:Yes?",
		   t_flushed, latest_mount_id, t_first, t_last);
    if (!fsck_user_confirmed (fs, "", "Yes\n", 1))
	die ("");

    /* replay transactions we have found */
    for (j_cur = t_offset; t_first <= t_last; t_first ++) {
	unsigned long offset;
	
	d_bh = bread (s->s_dev, j_start + j_cur, s->s_blocksize);
	j_desc = (struct reiserfs_journal_desc *)d_bh->b_data;
	if (who_is_this (d_bh->b_data, d_bh->b_size) != THE_JDESC ||
	    le32_to_cpu (j_desc->j_mount_id) != latest_mount_id ||
	    le32_to_cpu (j_desc->j_trans_id) != t_first)
	    die ("reiserfs_replay_journal: desc block not found");

	offset = j_cur + 1;
	j_cur += le32_to_cpu (j_desc->j_len) + 1;
	j_cur %= j_size;
	c_bh = bread (s->s_dev, j_start + j_cur, s->s_blocksize);
	j_commit = (struct reiserfs_journal_commit *)c_bh->b_data;
	if (does_desc_match_commit (j_desc, j_commit))
	    die ("reiserfs_replay_journal: commit block not found");

	fsck_log ("Mount_id %lu, transaction %lu, desc block %lu, commit block %lu: (",
		  latest_mount_id, t_first, d_bh->b_blocknr, c_bh->b_blocknr);

	/* replay one transaction */
	for (i = 0; i < le32_to_cpu (j_desc->j_len); i ++) {
	    struct buffer_head * in_place, * log;
	    unsigned long block;

	    log = bread (s->s_dev, j_start + ((offset + i) % j_size), s->s_blocksize);

	    if (i < JOURNAL_TRANS_HALF) {
		block = le32_to_cpu (j_desc->j_realblock[i]);
	    } else {
		block = le32_to_cpu (j_commit->j_realblock[i - JOURNAL_TRANS_HALF]);
	    }

	    if (not_journalable (s, block)) {
		fsck_log ("transaction %lu, block %d could not be replayed (%lu)\n",
			      t_first, i, block);
	    } else {
		fsck_log (" %lu", block);
		
		in_place = getblk (s->s_dev, block, s->s_blocksize) ;
		memcpy (in_place->b_data, log->b_data, s->s_blocksize);
		mark_buffer_dirty (in_place);
		mark_buffer_uptodate (in_place, 1);
		bwrite (in_place);
		brelse (in_place);
	    }
	    brelse (log);
	    
	}
	fsck_log (")\n");

	brelse (d_bh);
	brelse (c_bh);
	j_cur ++;
	j_cur %= j_size;

	/* update journal header */
	j_head->j_last_flush_trans_id = cpu_to_le32 (t_first);
	mark_buffer_dirty (jh_bh);
	bwrite (jh_bh);
    }

    brelse (jh_bh);
    fsck_progress ("Journal replaied\n");
    return 0;
}
