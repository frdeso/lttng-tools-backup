/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_H
#define LTTNG_H

/* Error codes that can be returned by API calls */
#include <lttng/lttng-error.h>

/* Include every LTTng ABI/API available. */
#include <lttng/channel.h>
#include <lttng/domain.h>
#include <lttng/event.h>
#include <lttng/handle.h>
#include <lttng/health.h>
#include <lttng/save.h>
#include <lttng/session.h>
#include <lttng/snapshot.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_calibrate_type {
	LTTNG_CALIBRATE_FUNCTION              = 0,
};

#define LTTNG_CALIBRATE_PADDING1           16
struct lttng_calibrate {
	enum lttng_calibrate_type type;

	char padding[LTTNG_CALIBRATE_PADDING1];
};

/*
 * Check if a session daemon is alive.
 *
 * Return 1 if alive or 0 if not. On error, returns a negative negative LTTng
 * error code.
 */
extern int lttng_session_daemon_alive(void);

/*
 * Set the tracing group for the *current* flow of execution.
 *
 * On success, returns 0 else a negative LTTng error code.
 */
extern int lttng_set_tracing_group(const char *name);

/*
 * This call registers an "outside consumer" for a session and an lttng domain.
 * No consumer will be spawned and all fds/commands will go through the socket
 * path given (socket_path).
 *
 * NOTE that this is not recommended unless you absolutely know what you are
 * doing.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_register_consumer(struct lttng_handle *handle,
		const char *socket_path);

/*
 * Start tracing for *all* domain(s) in the session.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_start_tracing(const char *session_name);

/*
 * Stop tracing for *all* domain(s) in the session.
 *
 * This call will wait for data availability for each domain of the session so
 * this can take an abritrary amount of time. However, when returning you have
 * the guarantee that the data is ready to be read and analyze. Use the
 * _no_wait call below to avoid this behavior.
 *
 * The session_name can't be NULL.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_stop_tracing(const char *session_name);

/*
 * Behave exactly like lttng_stop_tracing but does not wait for data
 * availability.
 */
extern int lttng_stop_tracing_no_wait(const char *session_name);

/*
 * Add context to event(s) for a specific channel (or for all).
 *
 * If channel_name is NULL, a lookup of the event's channel is done. If both
 * are NULL, the context is applied to all events of all channels.
 *
 * Note that whatever event_name value is, a context can not be added to an
 * event, so we just ignore it for now.
 */
extern int lttng_add_context(struct lttng_handle *handle,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name);

/*
 * Create or enable an event (or events) for a channel.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If channel_name is NULL, the default channel is used (channel0).
 *
 * The handle and ev params can not be NULL.
 */
extern int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name);

/*
 * Create or enable an event with a specific filter.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If ev is NULL, all events are enabled with that filter.
 * If channel_name is NULL, the default channel is used (channel0) and created
 * if not found.
 * If filter_expression is NULL, an event without associated filter is
 * created.
 */
extern int lttng_enable_event_with_filter(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression);

/*
 * Create or enable an event with a filter and/or exclusions.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If ev is NULL, all events are enabled with the filter and exclusion options.
 * If channel_name is NULL, the default channel is used (channel0) and created
 * if not found.
 * If filter_expression is NULL, an event without associated filter is
 * created.
 * If exclusion count is zero, the event will be created without exclusions.
 */
extern int lttng_enable_event_with_exclusions(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression,
		int exclusion_count, char **exclusion_names);

/*
 * Create or enable an event with a filter and/or instrument target.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If ev is NULL, all events are enabled with the filter and exclusion options.
 * If channel_name is NULL, the default channel is used (channel0) and created
 * if not found.
 * If filter_expression is NULL, an event without associated filter is
 * created.
 * If target path is NULL, the event will be created without target.
 */
extern int lttng_enable_event_with_target(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression, const char *target_path);

/*
 * Create or enable a channel.
 *
 * The chan and handle params can not be NULL.
 */
extern int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *chan);

/*
 * Disable event(s) of a channel and domain.
 *
 * If name is NULL, all events are disabled.
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_disable_event(struct lttng_handle *handle,
		const char *name, const char *channel_name);

/*
 * Disable channel.
 *
 */
extern int lttng_disable_channel(struct lttng_handle *handle,
		const char *name);

/*
 * Calibrate LTTng overhead.
 *
 * The chan and handle params can not be NULL.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate);

/*
 * Set URL for a consumer for a session and domain.
 *
 * Both data and control URL must be defined. If both URLs are the same, only
 * the control URL is used even for network streaming.
 *
 * Default port are 5342 and 5343 respectively for control and data which uses
 * the TCP protocol.
 *
 * URL format: proto://[HOST|IP][:PORT1[:PORT2]][/TRACE_PATH]
 *
 * Possible protocols are:
 * > file://...
 *   Local filesystem full path.
 *
 * > net[6]://...
 *   This will use the default network transport layer which is TCP for both
 *   control (PORT1) and data port (PORT2).
 *
 * > tcp[6]://...
 *   TCP only streaming. For this one, both data and control URL must be given.
 *
 * Return 0 on success else a negative LTTng error code.
 */
extern int lttng_set_consumer_url(struct lttng_handle *handle,
		const char *control_url, const char *data_url);

/*
 * For a given session name, this call checks if the data is ready to be read
 * or is still being extracted by the consumer(s) (pending) hence not ready to
 * be used by any readers.
 *
 * Return 0 if there is _no_ data pending in the buffers thus having a
 * guarantee that the data can be read safely. Else, return 1 if there is still
 * traced data is pending. On error, a negative value is returned and readable
 * by lttng_strerror().
 */
extern int lttng_data_pending(const char *session_name);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_H */
