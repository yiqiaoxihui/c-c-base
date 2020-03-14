#include "StdAfx.h"

//#include "Base.h"
#include "tvbuff.h"
#include "pint.h"
#include "tvbuff-int.h"
#include "charsets.h"
#include "proto.h"
#include "wmem_strbuf.h"

static const unsigned char left_aligned_bitmask[] = {
	0xff,
	0x80,
	0xc0,
	0xe0,
	0xf0,
	0xf8,
	0xfc,
	0xfe
};

static inline const guint8* fast_ensure_contiguous(tvbuff_t *tvb, const gint offset, const guint length)
{
	guint end_offset;
	guint u_offset;

	if (offset < 0 || !tvb->real_data) {
		//return ensure_contiguous(tvb, offset, length);
	}

	u_offset = offset;
	end_offset = u_offset + length;
	
	if (/*G_LIKELY*/(end_offset <= tvb->length)) {
		return tvb->real_data + u_offset;
	}/* else if (end_offset <= tvb->contained_length) {
		THROW(BoundsError);
	} else if (end_offset <= tvb->reported_length) {
		THROW(ContainedBoundsError);
	} else if (tvb->flags & TVBUFF_FRAGMENT) {
		THROW(FragmentBoundsError);
	} else {
		THROW(ReportedBoundsError);
	}*/
	/* not reached */
	return NULL;
}

guint16 tvb_get_ntohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pntoh16(ptr);
}
guint32 tvb_get_ntohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
	return pntoh32(ptr);
}

/* ---------------- */
guint8 tvb_get_guint8(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 1);
	return *ptr;
}

guint32 tvb_get_ntoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pntoh24(ptr);
}

guint64 tvb_get_ntoh40(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 5);
	return pntoh40(ptr);
}

guint64 tvb_get_ntoh48(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 6);
	return pntoh48(ptr);
}

guint64 tvb_get_ntoh56(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 7);
	return pntoh56(ptr);
}

guint64 tvb_get_ntoh64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 8);
	return pntoh64(ptr);
}

guint16 tvb_get_letohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pletoh16(ptr);
}

guint32 tvb_get_letohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
	return pletoh32(ptr);
}

guint32 tvb_get_letoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}


guint64 tvb_get_letoh40(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 5);
	return pletoh40(ptr);
}

guint64 tvb_get_letoh48(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 6);
	return pletoh48(ptr);
}

guint64 tvb_get_letoh56(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 7);
	return pletoh56(ptr);
}

guint64 tvb_get_letoh64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 8);
	return pletoh64(ptr);
}


static const guint8 bit_mask8[] = {
	0x00,
	0x01,
	0x03,
	0x07,
	0x0f,
	0x1f,
	0x3f,
	0x7f,
	0xff
};
guint64 _tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits)
{
	guint64 value;
	guint	octet_offset = bit_offset >> 3;
	guint8	required_bits_in_first_octet = 8 - (bit_offset % 8);

	if(required_bits_in_first_octet > total_no_of_bits)
	{
		/* the required bits don't extend to the end of the first octet */
		guint8 right_shift = required_bits_in_first_octet - total_no_of_bits;
		value = (tvb_get_guint8(tvb, octet_offset) >> right_shift) & bit_mask8[total_no_of_bits % 8];
	}
	else
	{	
		guint8 remaining_bit_length = total_no_of_bits;

		/* get the bits up to the first octet boundary */
		value = 0;
		required_bits_in_first_octet %= 8;
		if(required_bits_in_first_octet != 0)
		{
			value = tvb_get_guint8(tvb, octet_offset) & bit_mask8[required_bits_in_first_octet];
			remaining_bit_length -= required_bits_in_first_octet;
			octet_offset ++;
		}
		/* take the biggest words, shorts or octets that we can */
		while (remaining_bit_length > 7)
		{
			switch (remaining_bit_length >> 4)
			{
			case 0:
				/* 8 - 15 bits. (note that 0 - 7 would have dropped out of the while() loop) */
				value <<= 8;
				value += tvb_get_guint8(tvb, octet_offset);
				remaining_bit_length -= 8;
				octet_offset ++;
				break;

			case 1:
				/* 16 - 31 bits */
				value <<= 16;
				value += tvb_get_ntohs(tvb, octet_offset);
				remaining_bit_length -= 16;
				octet_offset += 2;
				break;

			case 2:
			case 3:
				/* 32 - 63 bits */
				value <<= 32;
				value += tvb_get_ntohl(tvb, octet_offset);
				remaining_bit_length -= 32;
				octet_offset += 4;
				break;

			default:
				/* 64 bits (or more???) */
				value = tvb_get_ntoh64(tvb, octet_offset);
				remaining_bit_length -= 64;
				octet_offset += 8;
				break;
			}
		}
		/* get bits from any partial octet at the tail */
		if(remaining_bit_length)
		{
			value <<= remaining_bit_length;
			value += (tvb_get_guint8(tvb, octet_offset) >> (8 - remaining_bit_length));
		}
	}
	return value;
}

inline int
	compute_offset(const tvbuff_t *tvb, const gint offset, guint *offset_ptr)
{
	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if ((guint) offset <= tvb->length) {
			*offset_ptr = offset;
		}/* else if ((guint) offset <= tvb->contained_length) {
			return BoundsError;
		} else if ((guint) offset <= tvb->reported_length) {
			return ContainedBoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else {
			return ReportedBoundsError;
		}*/
		else{
			return -1;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if ((guint) -offset <= tvb->length) {
			*offset_ptr = tvb->length + offset;
		} /*else if ((guint) -offset <= tvb->contained_length) {
			return BoundsError;
		} else if ((guint) -offset <= tvb->reported_length) {
			return ContainedBoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else {
			return ReportedBoundsError;
		}*/
		else{
			return -1;
		}
	}

	return 0;
}

inline int compute_offset_and_remaining(const tvbuff_t *tvb, const gint offset, guint *offset_ptr, guint *rem_len)
{
	int exception;

	exception = compute_offset(tvb, offset, offset_ptr);
	if (!exception)
		*rem_len = tvb->length - *offset_ptr;

	return exception;
}

guint tvb_ensure_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, rem_length = 0;
	int   exception;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
	{
		return 0;
	}
		//THROW(exception);

	//if (rem_length == 0) {
	//	/*
	//	 * This routine ensures there's at least one byte available.
	//	 * There aren't any bytes available, so throw the appropriate
	//	 * exception.
	//	 */
	//	//if (abs_offset < tvb->contained_length) {
	//	//	THROW(BoundsError);
	//	//} else if (abs_offset < tvb->reported_length) {
	//	//	THROW(ContainedBoundsError);
	//	//} else if (tvb->flags & TVBUFF_FRAGMENT) {
	//	//	THROW(FragmentBoundsError);
	//	//} else {
	//	//	THROW(ReportedBoundsError);
	//	//}
	//	
	//}
	return rem_length;
}

/* For tvbuff internal use */
static inline gint _tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, rem_length;
	int   exception;

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
		return 0;
	return rem_length;
}
/*
 * Check whether that offset goes more than one byte past the
 * end of the buffer.
 *
 * If not, return 0; otherwise, return exception
 */
static inline int
validate_offset(const tvbuff_t *tvb, const guint abs_offset)
{
	if ((abs_offset <= tvb->length)) {
		/* It's OK. */
		return 0;
	}

	/*
	 * It's not OK, but why?  Which boundaries is it
	 * past?
	 */
	if (abs_offset <= tvb->contained_length) {
		/*
		 * It's past the captured length, but not past
		 * the reported end of any parent tvbuffs from
		 * which this is constructed, or the reported
		 * end of this tvbuff, so it's out of bounds
		 * solely because we're past the end of the
		 * captured data.
		 */
		return -1;
	}

	/*
	 * There's some actual packet boundary, not just the
	 * artificial boundary imposed by packet slicing, that
	 * we're past.
	 */
	if (abs_offset <= tvb->reported_length) {
		/*
		 * We're within the bounds of what this tvbuff
		 * purportedly contains, based on some length
		 * value, but we're not within the bounds of
		 * something from which this tvbuff was
		 * extracted, so that length value ran past
		 * the end of some parent tvbuff.
		 */
		return -2;
	}

	/*
	 * OK, we're past the bounds of what this tvbuff
	 * purportedly contains.
	 */
	if (tvb->flags & TVBUFF_FRAGMENT) {
		/*
		 * This tvbuff is the first fragment of a larger
		 * packet that hasn't been reassembled, so we
		 * assume that's the source of the prblem - if
		 * we'd reassembled the packet, we wouldn't
		 * have gone past the end.
		 *
		 * That might not be true, but for at least
		 * some forms of reassembly, such as IP
		 * reassembly, you don't know how big the
		 * reassembled packet is unless you reassemble
		 * it, so, in those cases, we can't determine
		 * whether we would have gone past the end
		 * had we reassembled the packet.
		 */
		return -4;
	}

	/*
	 * OK, it looks as if we ran past the claimed length
	 * of data.
	 */
	return -3;
}
/* Computes the absolute offset and length based on a possibly-negative offset
 * and a length that is possible -1 (which means "to the end of the data").
 * Returns integer indicating whether the offset is in bounds (0) or
 * not (exception number). The integer ptrs are modified with the new offset,
 * captured (available) length, and contained length (amount that's present
 * in the parent tvbuff based on its reported length).
 * No exception is thrown; on success, we return 0, otherwise we return an
 * exception for the caller to throw if appropriate.
 *
 * XXX - we return success (0), if the offset is positive and right
 * after the end of the tvbuff (i.e., equal to the length).  We do this
 * so that a dissector constructing a subset tvbuff for the next protocol
 * will get a zero-length tvbuff, not an exception, if there's no data
 * left for the next protocol - we want the next protocol to be the one
 * that gets an exception, so the error is reported as an error in that
 * protocol rather than the containing protocol.  */
static inline int
check_offset_length_no_exception(const tvbuff_t *tvb,
				 const gint offset, gint const length_val,
				 guint *offset_ptr, guint *length_ptr)
{
	guint end_offset;
	int   exception;

	//DISSECTOR_ASSERT(offset_ptr);
	//DISSECTOR_ASSERT(length_ptr);

	/* Compute the offset */
	exception = compute_offset(tvb, offset, offset_ptr);
	if (exception)
		return exception;

	if (length_val < -1) {
		/* XXX - ReportedBoundsError? */
		return -1;
	}

	/* Compute the length */
	if (length_val == -1)
		*length_ptr = tvb->length - *offset_ptr;
	else
		*length_ptr = length_val;

	/*
	 * Compute the offset of the first byte past the length.
	 */
	end_offset = *offset_ptr + *length_ptr;

	/*
	 * Check for an overflow
	 */
	if (end_offset < *offset_ptr)
	{
		return -1;
	}
		//return BoundsError;

	return validate_offset(tvb, end_offset);
}

/* Checks (+/-) offset and length and throws an exception if
 * either is out of bounds. Sets integer ptrs to the new offset
 * and length. */
static inline void check_offset_length(const tvbuff_t *tvb, const gint offset, gint const length_val,guint *offset_ptr, guint *length_ptr)
{
	int exception;

	exception = check_offset_length_no_exception(tvb, offset, length_val, offset_ptr, length_ptr);
	if (exception)
	{
		print_error("check_offset_length exception not 0");
		THROW(exception);
	}
}

void tvb_check_offset_length(const tvbuff_t *tvb,const gint offset, gint const length_val,guint *offset_ptr, guint *length_ptr)
{
	check_offset_length(tvb, offset, length_val, offset_ptr, length_ptr);
}

tvbuff_t *
	tvb_new(/*const struct tvb_ops *ops*/)
{
	tvbuff_t *tvb;
	//gsize     size = ops->tvb_size;

	//g_assert(size >= sizeof(*tvb));

	//tvb = (tvbuff_t *) g_slice_alloc(size);
	tvb = new tvbuff_t;
	tvb->next		 = NULL;
	//tvb->ops		 = ops;
	tvb->initialized	 = FALSE;
	tvb->flags		 = 0;
	tvb->length		 = 0;
	tvb->reported_length	 = 0;
	tvb->contained_length	 = 0;
	tvb->real_data		 = NULL;
	tvb->raw_offset		 = -1;
	tvb->ds_tvb		 = NULL;

	return tvb;
}

static tvbuff_t *
tvb_new_with_subset(tvbuff_t *backing, const guint reported_length,
    const guint subset_tvb_offset, const guint subset_tvb_length)
{
	tvbuff_t *tvb = tvb_new(/*&tvb_subset_ops*/);
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	subset_tvb->subset.offset = subset_tvb_offset;
	subset_tvb->subset.length = subset_tvb_length;

	subset_tvb->subset.tvb	     = backing;
	tvb->length		     = subset_tvb_length;
	/*
	 * The contained length must not exceed what remains in the
	 * backing tvbuff.
	 */
	tvb->contained_length        = MIN(reported_length, backing->contained_length - subset_tvb_offset);
	tvb->flags		     = backing->flags;

	tvb->reported_length	     = reported_length;
	tvb->initialized	     = TRUE;

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	 * then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + subset_tvb_offset;
	}

	/*
	 * The top-level data source of this tvbuff is the top-level
	 * data source of its parent.
	 */
	tvb->ds_tvb = backing->ds_tvb;

	return tvb;
}
tvbuff_t * tvb_new_subset_length_caplen(tvbuff_t *backing, const gint backing_offset, const gint backing_length, const gint reported_length)
{
	tvbuff_t *tvb;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;
	guint	  actual_reported_length;

	//DISSECTOR_ASSERT(backing && backing->initialized);
	//THROW_ON(reported_length < -1, ReportedBoundsError);
	tvb_check_offset_length(backing, backing_offset, backing_length,&subset_tvb_offset,&subset_tvb_length);

	if (reported_length == -1)
		actual_reported_length = backing->reported_length - subset_tvb_offset;
	else
		actual_reported_length = (guint)reported_length;

	tvb = tvb_new_with_subset(backing, actual_reported_length,subset_tvb_offset, subset_tvb_length);

	//tvb_add_to_chain(backing, tvb);

	return tvb;
}





static inline const guint8*
ensure_contiguous_no_exception(tvbuff_t *tvb, const gint offset, const gint length, int *pexception)
{
	guint abs_offset = 0, abs_length = 0;
	int   exception;

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception) {
		if (pexception)
			*pexception = exception;
		return NULL;
	}

	/*
	 * Special case: if the caller (e.g. tvb_get_ptr) requested no data,
	 * then it is acceptable to have an empty tvb (!tvb->real_data).
	 */
	if (length == 0) {
		return NULL;
	}

	/*
	 * We know that all the data is present in the tvbuff, so
	 * no exceptions should be thrown.
	 */
	//in SIP,we only use real_data
	if (tvb->real_data)
		return tvb->real_data + abs_offset;

	//if (tvb->ops->tvb_get_ptr)
	//	return tvb->ops->tvb_get_ptr(tvb, abs_offset, abs_length);

	//DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
}

static inline const guint8*
	ensure_contiguous(tvbuff_t *tvb, const gint offset, const gint length)
{
	int           exception = 0;
	const guint8 *p;

	p = ensure_contiguous_no_exception(tvb, offset, length, &exception);
	if (p == NULL && length != 0) {
		//DISSECTOR_ASSERT(exception > 0);
		print_error("ensurce_contiguous get p ==NULL");
		THROW(exception);
	}
	return p;
}

//tvbuff_real.c
tvbuff_t *
tvb_new_real_data(const guint8* data, const guint length, const gint reported_length)
{
	tvbuff_t *tvb;
	//struct tvb_real *real_tvb;

	//THROW_ON(reported_length < -1, ReportedBoundsError);

	tvb = tvb_new(/*&tvb_real_ops*/);

	tvb->real_data           = data;
	tvb->length              = length;
	tvb->reported_length     = reported_length;
	tvb->contained_length    = reported_length;
	tvb->initialized         = TRUE;

	/*
	 * This is the top-level real tvbuff for this data source,
	 * so its data source tvbuff is itself.
	 */
	tvb->ds_tvb = tvb;

	//real_tvb = (struct tvb_real *) tvb;
	//real_tvb->free_cb = NULL;

	return tvb;
}
//tvbuff_real.c
tvbuff_t *
	tvb_new_child_real_data(tvbuff_t *parent, const guint8* data, const guint length, const gint reported_length)
{
	tvbuff_t *tvb = tvb_new_real_data(data, length, reported_length);

	//tvb_set_child_real_data_tvbuff(parent, tvb);

	return tvb;
}

tvbuff_t * tvb_new_octet_aligned(tvbuff_t *tvb, guint32 bit_offset, gint32 no_of_bits)
{
	tvbuff_t     *sub_tvb = NULL;
	guint32       byte_offset;
	gint32        datalen, i;
	guint8        left, right, remaining_bits, *buf;
	const guint8 *data;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	byte_offset = bit_offset >> 3;
	left = bit_offset % 8; /* for left-shifting */
	right = 8 - left; /* for right-shifting */

	if (no_of_bits == -1) {
		datalen = _tvb_captured_length_remaining(tvb, byte_offset);		//1.byte_offset>0 ,tvb->length - byte_offset, 2.byte_offset<0 ,tvb->length + byte_offset
		remaining_bits = 0;
	} else {
		datalen = no_of_bits >> 3;
		remaining_bits = no_of_bits % 8;
		if (remaining_bits) {
			datalen++;
		}
	}

	/* already aligned -> shortcut */
	if ((left == 0) && (remaining_bits == 0)) {
		return tvb_new_subset_length_caplen(tvb, byte_offset, datalen, datalen);
	}

	//DISSECTOR_ASSERT(datalen>0);

	/* if at least one trailing byte is available, we must use the content
	* of that byte for the last shift (i.e. tvb_get_ptr() must use datalen + 1
	* if non extra byte is available, the last shifted byte requires
	* special treatment
	*/
	if (_tvb_captured_length_remaining(tvb, byte_offset) > datalen) {
		data = ensure_contiguous(tvb, byte_offset, datalen + 1); /* tvb_get_ptr */

		/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
		buf = (guint8 *)malloc(datalen);

		/* shift tvb data bit_offset bits to the left */
		for (i = 0; i < datalen; i++)
			buf[i] = (data[i] << left) | (data[i+1] >> right);
	} else {
		data = ensure_contiguous(tvb, byte_offset, datalen); /* tvb_get_ptr() */

		/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
		buf = (guint8 *)malloc(datalen);

		/* shift tvb data bit_offset bits to the left */
		for (i = 0; i < (datalen-1); i++)
			buf[i] = (data[i] << left) | (data[i+1] >> right);
		buf[datalen-1] = data[datalen-1] << left; /* set last octet */
	}
	buf[datalen-1] &= left_aligned_bitmask[remaining_bits];

	sub_tvb = tvb_new_child_real_data(tvb, buf, datalen, datalen);
	//tvb_set_free_cb(sub_tvb, g_free);

	return sub_tvb;
}


//to_str.c

static inline char
low_nibble_of_octet_to_hex(guint8 oct)
{
	/* At least one version of Apple's C compiler/linker is buggy, causing
	   a complaint from the linker about the "literal C string section"
	   not ending with '\0' if we initialize a 16-element "char" array with
	   a 16-character string, the fact that initializing such an array with
	   such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
	   '\0' byte in the string nonwithstanding. */
	static const gchar hex_digits[16] =
	{ '0', '1', '2', '3', '4', '5', '6', '7',
	  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	return hex_digits[oct & 0xF];
}
//to_str.c
static inline char *byte_to_hex(char *out, guint32 dword)
{
	*out++ = low_nibble_of_octet_to_hex(dword >> 4);
	*out++ = low_nibble_of_octet_to_hex(dword);
	return out;
}

char* bytes_to_hexstr(char *out, const guint8 *ad, guint32 len)
{
	guint32 i;
	
	//if (!ad)
	//	REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_hexstr()");

	for (i = 0; i < len; i++)
	{
		out = byte_to_hex(out, ad[i]);
	}

	return out;
}


char* bytes_to_str(/*wmem_allocator_t *scope,*/ const guint8 *bd, int bd_len)
{
	gchar *cur=NULL;
	gchar *cur_ptr;
	int truncated = 0;

	if (!bd)
		/*REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_str()");*/
		return NULL;

	//cur=(gchar *)wmem_alloc(scope, MAX_BYTE_STR_LEN+3+1);
	cur=(gchar *)malloc( bd_len * 2 + 1);		//一个字节变长
	cur[bd_len * 2]='\0';
	if (bd_len <= 0) { cur[0] = '\0'; return cur; }
	//if (bd_len > MAX_BYTE_STR_LEN/2) {	/* bd_len > 24 */
	//	truncated = 1;
	//	bd_len = MAX_BYTE_STR_LEN/2;
	//}
	cur_ptr=bytes_to_hexstr(cur, bd, bd_len);	/* max MAX_BYTE_STR_LEN bytes */
	//if (truncated)
	//	cur_ptr = g_stpcpy(cur_ptr, UTF8_HORIZONTAL_ELLIPSIS);	/* 3 bytes */
	*cur_ptr = '\0';				/* 1 byte */
	//content=std::string(cur);	//致命错误，转化成string时应该使用指针头，而不是指针尾部
	//free(cur);				
	return cur;
}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
gchar *tvb_bytes_to_str(tvbuff_t *tvb, const gint offset, const gint len)
{
	return bytes_to_str(ensure_contiguous(tvb, offset, len), len);
}


gchar *tvb_get_ascii_7bits_string(/*wmem_allocator_t *scope,*/ tvbuff_t *tvb,const gint bit_offset, gint no_of_chars)
{
	gint           in_offset = bit_offset >> 3; /* Current pointer to the input buffer */
	gint           length = ((no_of_chars + 1) * 7 + (bit_offset & 0x07)) >> 3;
	const guint8  *ptr;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, in_offset, length);
	return get_ascii_7bits_string(ptr, bit_offset, no_of_chars);

}


/*
 * All string functions below take a scope as an argument.
 *
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitly free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 *
 * All functions throw an exception if the tvbuff ends before the string
 * does.
 */

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, offset, and length as an ASCII string,
 * with all bytes with the high-order bit set being invalid, and return a
 * pointer to a UTF-8 string, allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
static guint8 *
tvb_get_ascii_string(/*wmem_allocator_t *scope, */tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ascii_string(/*scope, */ptr, length);
}

static gint
	tvb_find_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = ensure_contiguous(tvb, abs_offset, limit); /* tvb_get_ptr() */

	result = (const guint8 *) memchr(ptr, needle, limit);
	if (!result)
		return -1;

	return (gint) ((result - ptr) + abs_offset);
}
/* Find first occurrence of needle in tvbuff, starting at offset. Searches
 * at most maxlength number of bytes; if maxlength is -1, searches to
 * end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_find_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 needle)
{
	const guint8 *result;
	guint	      abs_offset = 0;
	guint	      limit = 0;
	int           exception;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &limit);
	if (exception)
	{
		print_error("compute_offset_and_remaining exception !=0");
		THROW(exception);
	}

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength >= 0 && limit > (guint) maxlength) {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = (guint) maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = (const guint8 *)memchr(tvb->real_data + abs_offset, needle, limit);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint) (result - tvb->real_data);
		}
	}

	//if (tvb->ops->tvb_find_guint8)
	//	return tvb->ops->tvb_find_guint8(tvb, abs_offset, limit, needle);

	return tvb_find_guint8_generic(tvb, offset, limit, needle);
}
/* Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
guint
tvb_strsize(tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, junk_length;
	gint  nul_offset;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);
	nul_offset = tvb_find_guint8(tvb, abs_offset, -1, 0);
	if (nul_offset == -1) {
		/*
		 * OK, we hit the end of the tvbuff, so we should throw
		 * an exception.
		 */
		
		print_error("tvb_strsize nul_offset-1 , hit the end of the tvbuff");
		if (tvb->length < tvb->contained_length) {
			THROW(/*BoundsError*/);
		} else if (tvb->length < tvb->reported_length) {
			THROW(/*ContainedBoundsError*/);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(/*FragmentBoundsError*/);
		} else {
			THROW(/*ReportedBoundsError*/);
		}
	}
	return (nul_offset - abs_offset) + 1;
}



static guint8 *tvb_get_stringz_unichar2(/*wmem_allocator_t *scope, */tvbuff_t *tvb, gint offset, gint *lengthp, const gunichar2 table[0x80])
{
	guint size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_unichar2_string(/*scope, */ptr, size, table);
}

/*
 * Given a wmem scope, a tvbuff, an offset, a length, and an encoding
 * giving the byte order, treat the string of bytes referred to by the
 * tvbuff, the offset, and the length as a UCS-2 encoded string in
 * the byte order in question, containing characters from the Basic
 * Multilingual Plane (plane 0) of Unicode, and return a pointer to a
 * UTF-8 string, allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN.
 *
 * Specify length in bytes.
 *
 * XXX - should map lead and trail surrogate values to REPLACEMENT
 * CHARACTERs (0xFFFD)?
 * XXX - if there are an odd number of bytes, should put a
 * REPLACEMENT CHARACTER at the end.
 */
static guint8 *tvb_get_ucs_2_string(/*wmem_allocator_t *scope, */tvbuff_t *tvb, const gint offset, gint length, const guint encoding)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ucs_2_string(/*scope, */ptr, length, encoding);
}

/*
 * Given a tvbuff, an offset, a length, and an encoding, allocate a
 * buffer big enough to hold a non-null-terminated string of that length
 * at that offset, plus a trailing '\0', copy into the buffer the
 * string as converted from the appropriate encoding to UTF-8, and
 * return a pointer to the string.
 */
guint8 *tvb_get_string_enc(/*wmem_allocator_t *scope, */tvbuff_t *tvb, const gint offset,
			     const gint length, const guint encoding)
{
	guint8 *strptr;

	//DISSECTOR_ASSERT(tvb && tvb->initialized);

	/* make sure length = -1 fails */
	if (length < 0) {
		/*THROW(ReportedBoundsError);*/
		return NULL;
	}

	switch (encoding & ENC_CHARENCODING_MASK) {

	case ENC_ASCII:
	default:
		/*
		 * For now, we treat bogus values as meaning
		 * "ASCII" rather than reporting an error,
		 * for the benefit of old dissectors written
		 * when the last argument to proto_tree_add_item()
		 * was a gboolean for the byte order, not an
		 * encoding value, and passed non-zero values
		 * other than TRUE to mean "little-endian".
		 */
		strptr = tvb_get_ascii_string(/*scope,*/ tvb, offset, length);
		break;

	case ENC_UTF_8:
		/*
		 * XXX - should map lead and trail surrogate value code
		 * points to a "substitute" UTF-8 character?
		 * XXX - should map code points > 10FFFF to REPLACEMENT
		 * CHARACTERs.
		 */
		//strptr = tvb_get_utf_8_string(scope, tvb, offset, length);
		break;

	case ENC_UTF_16:
		//strptr = tvb_get_utf_16_string(scope, tvb, offset, length,encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_2:
		strptr = tvb_get_ucs_2_string(/*scope, */tvb, offset, length, encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_4:
		//strptr = tvb_get_ucs_4_string(scope, tvb, offset, length,encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_ISO_8859_1:
		/*
		 * ISO 8859-1 printable code point values are equal
		 * to the equivalent Unicode code point value, so
		 * no translation table is needed.
		 */
		//strptr = tvb_get_string_8859_1(scope, tvb, offset, length);
		break;

	case ENC_ISO_8859_2:
		//strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_2);
		break;

	//case ENC_ISO_8859_3:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_3);
	//	break;

	//case ENC_ISO_8859_4:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_4);
	//	break;

	//case ENC_ISO_8859_5:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_5);
	//	break;

	//case ENC_ISO_8859_6:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_6);
	//	break;

	//case ENC_ISO_8859_7:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_7);
	//	break;

	//case ENC_ISO_8859_8:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_8);
	//	break;

	//case ENC_ISO_8859_9:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_9);
	//	break;

	//case ENC_ISO_8859_10:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_10);
	//	break;

	//case ENC_ISO_8859_11:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_11);
	//	break;

	//case ENC_ISO_8859_13:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_13);
	//	break;

	//case ENC_ISO_8859_14:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_14);
	//	break;

	//case ENC_ISO_8859_15:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_15);
	//	break;

	//case ENC_ISO_8859_16:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_16);
	//	break;

	//case ENC_WINDOWS_1250:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1250);
	//	break;

	//case ENC_WINDOWS_1251:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1251);
	//	break;

	//case ENC_WINDOWS_1252:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1252);
	//	break;

	//case ENC_MAC_ROMAN:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_mac_roman);
	//	break;

	//case ENC_CP437:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp437);
	//	break;

	//case ENC_CP855:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp855);
	//	break;

	//case ENC_CP866:
	//	strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp866);
	//	break;

	//case ENC_ISO_646_BASIC:
	//	strptr = tvb_get_iso_646_string(scope, tvb, offset, length, charset_table_iso_646_basic);
	//	break;

	//case ENC_3GPP_TS_23_038_7BITS:
	//	{
	//		gint bit_offset  = offset << 3;
	//		gint no_of_chars = (length << 3) / 7;
	//		strptr = tvb_get_ts_23_038_7bits_string(scope, tvb, bit_offset, no_of_chars);
	//	}
	//	break;

	case ENC_ASCII_7BITS:
		{
			gint bit_offset  = offset << 3;
			gint no_of_chars = (length << 3) / 7;
			strptr =(guint8 *) tvb_get_ascii_7bits_string(/*scope,*/ tvb, bit_offset, no_of_chars);
		}
		break;

	case ENC_EBCDIC:
		/*
		 * "Common" EBCDIC, covering all characters with the
		 * same code point in all Roman-alphabet EBCDIC code
		 * pages.
		 */
		//strptr = tvb_get_nonascii_unichar2_string(scope, tvb, offset, length, charset_table_ebcdic);
		break;

	case ENC_EBCDIC_CP037:
		/*
		 * EBCDIC code page 037.
		 */
		//strptr = tvb_get_nonascii_unichar2_string(scope, tvb, offset, length, charset_table_ebcdic_cp037);
		break;

	case ENC_T61:
		//strptr = tvb_get_t61_string(scope, tvb, offset, length);
		break;
	}
	return strptr;
}