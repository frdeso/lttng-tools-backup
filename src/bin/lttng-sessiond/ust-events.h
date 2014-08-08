#ifndef _LTTNG_UST_EVENTS_H
#define _LTTNG_UST_EVENTS_H

/*
 * lttng/ust-events.h
 *
 * Copyright 2010-2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2014 (c) - Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <urcu/list.h>
#include <urcu/hlist.h>
#include <stdint.h>
#include <lttng/ust-config.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-endian.h>
#include <float.h>
#include <errno.h>
#include <urcu/ref.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tracepoint provider version. Compatibility based on the major number.
 * Older tracepoint providers can always register to newer lttng-ust
 * library, but the opposite is rejected: a newer tracepoint provider is
 * rejected by an older lttng-ust library.
 */
#define LTTNG_UST_PROVIDER_MAJOR	1
#define LTTNG_UST_PROVIDER_MINOR	0

/*
 * Data structures used by tracepoint event declarations, and by the
 * tracer. Those structures have padding for future extension.
 */

/* Type description */

/* Update the astract_types name table in lttng-types.c along with this enum */
enum lttng_abstract_types {
	atype_integer,
	atype_enum,
	atype_array,
	atype_sequence,
	atype_string,
	atype_float,
	NR_ABSTRACT_TYPES,
};

/* Update the string_encodings name table in lttng-types.c along with this enum */
enum lttng_string_encodings {
	lttng_encode_none = 0,
	lttng_encode_UTF8 = 1,
	lttng_encode_ASCII = 2,
	NR_STRING_ENCODINGS,
};

#define LTTNG_UST_ENUM_ENTRY_PADDING	16
struct lttng_enum_entry {
	unsigned long long start, end;	/* start and end are inclusive */
	const char *string;
	char padding[LTTNG_UST_ENUM_ENTRY_PADDING];
};

#define __type_integer(_type, _byte_order, _base, _encoding)	\
	{							\
	  .atype = atype_integer,				\
	  .u =							\
		{						\
		  .basic = 					\
			{					\
			  .integer =				\
				{				\
				  .size = sizeof(_type) * CHAR_BIT,		\
				  .alignment = lttng_alignof(_type) * CHAR_BIT,	\
				  .signedness = lttng_is_signed_type(_type),	\
				  .reverse_byte_order = _byte_order != BYTE_ORDER, \
				  .base = _base,				\
				  .encoding = lttng_encode_##_encoding,		\
				}				\
			}					\
		},						\
	}							\

#define LTTNG_UST_INTEGER_TYPE_PADDING	24
struct lttng_integer_type {
	unsigned int size;		/* in bits */
	unsigned short alignment;	/* in bits */
	unsigned int signedness:1;
	unsigned int reverse_byte_order:1;
	unsigned int base;		/* 2, 8, 10, 16, for pretty print */
	enum lttng_string_encodings encoding;
	char padding[LTTNG_UST_INTEGER_TYPE_PADDING];
};

/*
 * Only float and double are supported. long double is not supported at
 * the moment.
 */
#define _float_mant_dig(_type)						\
	(sizeof(_type) == sizeof(float) ? FLT_MANT_DIG			\
		: (sizeof(_type) == sizeof(double) ? DBL_MANT_DIG	\
		: 0))

#define __type_float(_type)					\
	{							\
	  .atype = atype_float,					\
	  .u =							\
		{						\
		  .basic =					\
			{					\
			  ._float =				\
				{				\
				  .exp_dig = sizeof(_type) * CHAR_BIT		\
						  - _float_mant_dig(_type),	\
				  .mant_dig = _float_mant_dig(_type),		\
				  .alignment = lttng_alignof(_type) * CHAR_BIT,	\
				  .reverse_byte_order = BYTE_ORDER != FLOAT_WORD_ORDER,	\
				}				\
			}					\
		},						\
	}							\

#define LTTNG_UST_FLOAT_TYPE_PADDING	24
struct lttng_float_type {
	unsigned int exp_dig;		/* exponent digits, in bits */
	unsigned int mant_dig;		/* mantissa digits, in bits */
	unsigned short alignment;	/* in bits */
	unsigned int reverse_byte_order:1;
	char padding[LTTNG_UST_FLOAT_TYPE_PADDING];
};

#define LTTNG_UST_BASIC_TYPE_PADDING	128
union _lttng_basic_type {
	struct lttng_integer_type integer;
	struct {
		const char *name;
	} enumeration;
	struct {
		enum lttng_string_encodings encoding;
	} string;
	struct lttng_float_type _float;
	char padding[LTTNG_UST_BASIC_TYPE_PADDING];
};

struct lttng_basic_type {
	enum lttng_abstract_types atype;
	union {
		union _lttng_basic_type basic;
	} u;
};

#define LTTNG_UST_TYPE_PADDING	128
struct lttng_type {
	enum lttng_abstract_types atype;
	union {
		union _lttng_basic_type basic;
		struct {
			struct lttng_basic_type elem_type;
			unsigned int length;		/* num. elems. */
		} array;
		struct {
			struct lttng_basic_type length_type;
			struct lttng_basic_type elem_type;
		} sequence;
		char padding[LTTNG_UST_TYPE_PADDING];
	} u;
};

#define LTTNG_UST_ENUM_TYPE_PADDING	24
struct lttng_enum {
	const char *name;
	struct lttng_type container_type;
	const struct lttng_enum_entry *entries;
	unsigned int len;
	char padding[LTTNG_UST_ENUM_TYPE_PADDING];
};

/*
 * Event field description
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */

#define LTTNG_UST_EVENT_FIELD_PADDING	28
struct lttng_event_di_field {
	const char *name;
	struct lttng_type type;
	unsigned int nowrite;	/* do not write into trace */
	char padding[LTTNG_UST_EVENT_FIELD_PADDING];
};

#define LTTNG_UST_EVENT_DESC_PADDING	40
struct lttng_event_desc {
	const char *name;
	void (*probe_callback)(void);
	const struct lttng_event_ctx *ctx;	/* context */
	const struct lttng_event_field *fields;	/* event payload */
	unsigned int nr_fields;
	const int **loglevel;
	const char *signature;	/* Argument types/names received */
	union {
		struct {
			const char **model_emf_uri;
		} ext;
		char padding[LTTNG_UST_EVENT_DESC_PADDING];
	} u;
};

enum lttng_probe_type {
	LTTNG_PROBE_STATIC,
	LTTNG_PROBE_INSTRUMENT,
};

#define LTTNG_UST_PROBE_DESC_PADDING	8
struct lttng_probe_desc {
	const char *provider;
	const struct lttng_event_desc **event_desc;
	unsigned int nr_events;
	struct cds_list_head head;		/* chain registered probes */
	struct cds_list_head lazy_init_head;
	int lazy;				/* lazy registration */
	uint32_t major;
	uint32_t minor;
	enum lttng_probe_type type;
	char padding[LTTNG_UST_PROBE_DESC_PADDING];
};

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_EVENTS_H */
