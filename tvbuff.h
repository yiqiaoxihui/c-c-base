/* tvbuff.h
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
 *
 * "Testy" -- the buffer gets mad when an attempt is made to access data
 *      beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 *      the data of a backing tvbuff, or can be a composite of
 *      other tvbuffs.
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TVBUFF_H__
#define __TVBUFF_H__

#include "Base.h"

//#ifdef __cplusplus
//extern "C" {
//#endif /* __cplusplus */

/**
 * "testy, virtual(-izable) buffer".  They are testy in that they get mad when
 * an attempt is made to access data beyond the bounds of their array. In that
 * case, they throw an exception.
 *
 * They are virtualizable in that new tvbuff's can be made from other tvbuffs,
 * while only the original tvbuff may have data. That is, the new tvbuff has
 * virtual data.
 */



struct tvbuff;
typedef struct tvbuff tvbuff_t;
struct tvbuff {

	/* Doubly linked list pointers */
	tvbuff_t                *next;

	/* Record-keeping */
	const struct tvb_ops   *ops;
	gboolean		initialized;
	guint			flags;
	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */

	/** Pointer to the data for this tvbuff.
	 * It might be null, which either means that 1) it's a
	 * zero-length tvbuff or 2) the tvbuff was lazily
	 * constructed, so that we don't allocate a buffer of
	 * backing data and fill it in unless we need that
	 * data, e.g. when tvb_get_ptr() is called.
	 */
	const guint8		*real_data;

	/** Amount of data that's available from the capture
	 * file.  This is the length of virtual buffer (and/or
	 * real_data).  It may be less than the reported
	 * length if this is from a packet that was cut short
	 * by the capture process.
	 *
	 * This must never be > reported_length or contained_length. */
	guint			length;

	/** Amount of data that was reported as being in
	 * the packet or other data that this represents.
	 * As indicated above, it may be greater than the
	 * amount of data that's available. */
	guint			reported_length;

	/** If this was extracted from a parent tvbuff,
	 * this is the amount of extracted data that
	 * was reported as being in the parent tvbuff;
	 * if this represents a blob of data in that
	 * tvbuff that has a length specified by data
	 * in that tvbuff, it might be greater than
	 * the amount of data that was actually there
	 * to extract, so it could be greater than
	 * reported_length.
	 *
	 * If this wasn't extracted from a parent tvbuff,
	 * this is the same as reported_length.
	 *
	 * This must never be > reported_length. */
	guint			contained_length;

	/* Offset from beginning of first "real" tvbuff. */
	gint			raw_offset;
};
//tvbuff-subnet.c
typedef struct {
	/** The backing tvbuff_t */
	struct tvbuff	*tvb;

	/** The offset of 'tvb' to which I'm privy */
	guint		offset;
	/** The length of 'tvb' to which I'm privy */
	guint		length;

} tvb_backing_t;

struct tvb_subset {
	struct tvbuff tvb;

	tvb_backing_t	subset;
};

guint16 tvb_get_ntohs(tvbuff_t *tvb, const gint offset);
guint32 tvb_get_ntohl(tvbuff_t *tvb, const gint offset);
guint32 tvb_get_ntoh24(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_ntoh40(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_ntoh48(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_ntoh56(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_ntoh64(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_ntoh64(tvbuff_t *tvb, const gint offset);

guint16 tvb_get_letohs(tvbuff_t *tvb, const gint offset);
guint32 tvb_get_letohl(tvbuff_t *tvb, const gint offset);
guint32 tvb_get_letoh24(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_letoh40(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_letoh48(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_letoh56(tvbuff_t *tvb, const gint offset);
guint64 tvb_get_letoh64(tvbuff_t *tvb, const gint offset);



guint8 tvb_get_guint8(tvbuff_t *tvb, const gint offset);
guint64 _tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits);


tvbuff_t * tvb_new_octet_aligned(tvbuff_t *tvb, guint32 bit_offset, gint32 no_of_bits);

void tvb_get_ascii_7bits_string(/*wmem_allocator_t *scope, */tvbuff_t *tvb, const gint bit_offset, gint no_of_chars,std::string &content);


//16进制数字转16进制字符串
char* bytes_to_hexstr(char *out, const guint8 *ad, guint32 len,std::string &content);
char* bytes_to_str(/*wmem_allocator_t *scope,*/ const guint8 *bd, int bd_len);
gchar * tvb_bytes_to_str(tvbuff_t *tvb, const gint offset, const gint len);


//
gchar * tvb_get_ascii_7bits_string(/*wmem_allocator_t *scope,*/ tvbuff_t *tvb,const gint bit_offset, gint no_of_chars);
guint8 *tvb_get_string_enc(/*wmem_allocator_t *scope, */tvbuff_t *tvb, const gint offset,const gint length, const guint encoding);
guint tvb_ensure_captured_length_remaining(const tvbuff_t *tvb, const gint offset);
gint tvb_find_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 needle);
guint tvb_strsize(tvbuff_t *tvb, const gint offset);
//guint8 *get_unichar2_string(/*wmem_allocator_t *scope,*/ const guint8 *ptr, gint length, const gunichar2 table[0x80]);

#endif