/* vi: set sw=4 ts=4: */
/* Blackfin ELF shared library loader suppport
 *
 * Copyright (c) 1994-2000 Eric Youngdale, Peter MacDonald,
 *                              David Engel, Hongjiu Lu and Mitch D'Souza
 * Copyright (C) 2001-2004 Erik Andersen
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the above contributors may not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static const char *_dl_reltypes_tab[] =
{
  [0]	"R_BFIN_unused0",	"R_BFIN_pcrel5m2",
  [2]	"R_BFIN_unused1",	"R_BFIN_pcrel10",
  [4]	"R_BFIN_pcrel12_jump",	"R_BFIN_rimm16",
  [6]	"R_BFIN_luimm16",	"R_BFIN_huimm16",
  [8]	"R_BFIN_pcrel12_jump_s","R_BFIN_pcrel24_jump_x",
  [10]	"R_BFIN_pcrel24",	"R_BFIN_unusedb",
  [12]	"R_BFIN_unusedc",	"R_BFIN_pcrel24_jump_l",
  [14]	"R_BFIN_pcrel24_call_x","R_BFIN_var_eq_symb",
  [16]	"R_BFIN_byte_data",	"R_BFIN_byte2_data",	"R_BFIN_byte4_data",
  [19]	"R_BFIN_pcrel11",

  [20]	"R_BFIN_GOT17M4",	"R_BFIN_GOTHI",		"R_BFIN_GOTLO",
  [23]	"R_BFIN_FUNCDESC",
  [24]	"R_BFIN_FUNCDESC_GOT17M4",	"R_BFIN_FUNCDESC_GOTHI",	"R_BFIN_FUNCDESC_GOTLO",
  [27]	"R_BFIN_FUNCDESC_VALUE", "R_BFIN_FUNCDESC_GOTOFF17M4",
  [29]	"R_BFIN_FUNCDESC_GOTOFFHI", "R_BFIN_FUNCDESC_GOTOFFLO",
  [31]	"R_BFIN_GOTOFF17M4",	"R_BFIN_GOTOFFHI",	"R_BFIN_GOTOFFLO",
#if 0
  [200]	"R_BFIN_GNU_VTINHERIT",	"R_BFIN_GNU_VTENTRY"
#endif
};
