#include "StdAfx.h"
#include "proto.h"
#include "tvbuff.h"
//#include "ftypes.h"
#include "bits_ctz.h"
#include "tvbuff.h"
//void proto_tree_add_item_new(tvbuff_t *tvb,const gint start, gint length, enum tfenum type, guint64 bitmask, const guint encoding);
//{};

/*
case FT_CHAR:
case FT_UINT8:
case FT_UINT16:
case FT_UINT24:
case FT_UINT32:
获取小于32位的从offset起始 长度为length的  bitmask 对应位上等于1的 N=[1,32] bits 的数的值
eg. bitmask=0xf00000  ,tvb='0001 0011 0101 1010 1101',offset=0,length =3, result = 0001 =1 
*/
 guint32 get_lte_uint32_field_value(tvbuff_t *tvb, gint offset, gint length, guint64 bitmask,const guint encoding)
{
	guint32 value=get_uint_value(tvb,offset,length,encoding);
	guint32 result = proto_tree_set_uint(bitmask,value);
	return result;
}
 
 guint32 get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	guint32 value;
	gboolean length_error;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		if (encoding & ENC_ZIGBEE) {
			if (value == 0xFF) { /* Invalid Zigbee length, set to 0 */
				value = 0;
			}
		}
		break;

	case 2:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohs(tvb, offset)
			: tvb_get_ntohs(tvb, offset);
		if (encoding & ENC_ZIGBEE) {
			if (value == 0xFFFF) { /* Invalid Zigbee length, set to 0 */
				value = 0;
			}
		}
		break;

	case 3:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh24(tvb, offset)
			: tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohl(tvb, offset)
			: tvb_get_ntohl(tvb, offset);
		break;

	default:
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohl(tvb, offset)
				: tvb_get_ntohl(tvb, offset);
		}
		//report_type_length_mismatch(tree, "an unsigned integer", length, length_error);
		break;
	}
	return value;
}
/* Set the FT_UINT{8,16,24,32} value */
 guint32 proto_tree_set_uint(guint64 bitmask, guint32 value)
{
	//header_field_info *hfinfo;
	guint32		   integer;

	//hfinfo = fi->hfinfo;
	integer = value;

	if (bitmask) {
		/* Mask out irrelevant portions */
		integer &= (guint32)(bitmask);

		/* Shift bits */
		integer >>= hfinfo_bitshift(bitmask);
	}
	return integer;
	//fvalue_set_uinteger(&fi->value, integer);
}

/*
case FT_UINT40:
case FT_UINT48:
case FT_UINT56:
case FT_UINT64:
*/
 guint64 get_lte_uint64_field_value(tvbuff_t *tvb, gint offset, gint length, guint64 bitmask,const guint encoding)
{
	guint64 value=get_uint64_value(tvb,offset,length,encoding);
	guint64 result = proto_tree_set_uint64(bitmask,value);
	return result;
}
 inline guint64 get_uint64_value(tvbuff_t *tvb, gint offset, guint length, const guint encoding)
{
	guint64 value;
	gboolean length_error;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohs(tvb, offset)
			: tvb_get_ntohs(tvb, offset);
		break;

	case 3:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh24(tvb, offset)
			: tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohl(tvb, offset)
			: tvb_get_ntohl(tvb, offset);
		break;

	case 5:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh40(tvb, offset)
			: tvb_get_ntoh40(tvb, offset);
		break;

	case 6:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh48(tvb, offset)
			: tvb_get_ntoh48(tvb, offset);
		break;

	case 7:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh56(tvb, offset)
			: tvb_get_ntoh56(tvb, offset);
		break;

	case 8:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh64(tvb, offset)
			: tvb_get_ntoh64(tvb, offset);
		break;

	default:
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh64(tvb, offset)
				: tvb_get_ntoh64(tvb, offset);
		}
		//report_type_length_mismatch(tree, "an unsigned integer", length, length_error);
		print_error("get_uint64_value: an unsigned integer");
		break;
	}
	return value;
}
int hfinfo_bitshift(guint64 bitmask)
{
	int num=ws_ctz(bitmask);
	return num;
}

/* Set the FT_UINT{40,48,56,64} value */
 guint64 proto_tree_set_uint64(guint64 bitmask, guint64 value)
{
	//header_field_info *hfinfo;
	guint64		   integer;
	//hfinfo = fi->hfinfo;
	integer = value;
	int right_shift=0;
	if (bitmask) {
		/* Mask out irrelevant portions */
		integer &= bitmask;

		/* Shift bits */
		right_shift=hfinfo_bitshift(bitmask);
		integer >>= right_shift;
	}
	return integer;
	//TODO
	//fvalue_set_uinteger64(&fi->value, integer);
}

 /* For FT_STRING */
 /*static*/ /*inline const*/ guint8 *
	 get_string_value(/*wmem_allocator_t *scope,*/ tvbuff_t *tvb, gint start,
	 gint length, /*gint *ret_length,*/ const guint encoding)
 {
	 if (length == -1) {
		 length = tvb_ensure_captured_length_remaining(tvb, start);
	 }
	 //*ret_length = length;
	 return tvb_get_string_enc(/*scope, */tvb, start, length, encoding);
 }

