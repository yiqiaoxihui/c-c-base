/* tvbuff-int.h
 *
 * Structures that most TVB users should not be accessing directly.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TVBUFF_INT_H__
#define __TVBUFF_INT_H__

//struct tvbuff;
//struct tvbuff {
//	/* Doubly linked list pointers */
//	tvbuff_t                *next;
//
//	/* Record-keeping */
//	const struct tvb_ops   *ops;
//	gboolean		initialized;
//	guint			flags;
//	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */
//
//	/** Pointer to the data for this tvbuff.
//	 * It might be null, which either means that 1) it's a
//	 * zero-length tvbuff or 2) the tvbuff was lazily
//	 * constructed, so that we don't allocate a buffer of
//	 * backing data and fill it in unless we need that
//	 * data, e.g. when tvb_get_ptr() is called.
//	 */
//	const guint8		*real_data;
//
//	/** Amount of data that's available from the capture
//	 * file.  This is the length of virtual buffer (and/or
//	 * real_data).  It may be less than the reported
//	 * length if this is from a packet that was cut short
//	 * by the capture process.
//	 *
//	 * This must never be > reported_length or contained_length. */
//	guint			length;
//
//	/** Amount of data that was reported as being in
//	 * the packet or other data that this represents.
//	 * As indicated above, it may be greater than the
//	 * amount of data that's available. */
//	guint			reported_length;
//
//	/** If this was extracted from a parent tvbuff,
//	 * this is the amount of extracted data that
//	 * was reported as being in the parent tvbuff;
//	 * if this represents a blob of data in that
//	 * tvbuff that has a length specified by data
//	 * in that tvbuff, it might be greater than
//	 * the amount of data that was actually there
//	 * to extract, so it could be greater than
//	 * reported_length.
//	 *
//	 * If this wasn't extracted from a parent tvbuff,
//	 * this is the same as reported_length.
//	 *
//	 * This must never be > reported_length. */
//	guint			contained_length;
//
//	/* Offset from beginning of first "real" tvbuff. */
//	gint			raw_offset;
//};
#define TVBUFF_FRAGMENT		0x00000001	/* this is a fragment */


#endif