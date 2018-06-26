/*
 * AVTP Audio Format (AAF) PCM Plugin
 *
 * Copyright (c) 2018, Intel Corporation
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <arpa/inet.h>
#include <avtp.h>
#include <avtp_aaf.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#ifdef AAF_DEBUG
#define pr_debug(...) SNDERR(__VA_ARGS__)
#else
#define pr_debug(...) (void)0
#endif

#define CLOCK_REF		CLOCK_REALTIME
#define NSEC_PER_SEC		1000000000ULL
#define NSEC_PER_USEC		1000ULL

#define FD_COUNT_PLAYBACK	1

typedef struct {
	snd_pcm_ioplug_t io;

	char ifname[IFNAMSIZ];
	uint8_t addr[ETH_ALEN];
	int prio;
	uint64_t streamid;
	int mtt;
	int t_uncertainty;
	int frames_per_pkt;

	int sk_fd;
	int timer_fd;

	struct sockaddr_ll sk_addr;

	char *audiobuf;

	struct avtp_stream_pdu *pdu;
	int pdu_size;
	uint8_t pdu_seq;

	uint64_t mclk_start_time;
	uint64_t mclk_period;
	uint64_t mclk_ticks;

	snd_pcm_channel_area_t *audiobuf_areas;
	snd_pcm_channel_area_t *payload_areas;

	snd_pcm_sframes_t hw_ptr;
	snd_pcm_sframes_t buffer_size;
	snd_pcm_sframes_t boundary;
} snd_pcm_aaf_t;

static unsigned int alsa_to_avtp_format(snd_pcm_format_t format)
{
	switch (format) {
	case SND_PCM_FORMAT_S16_BE:
		return AVTP_AAF_FORMAT_INT_16BIT;
	case SND_PCM_FORMAT_S24_3BE:
		return AVTP_AAF_FORMAT_INT_24BIT;
	case SND_PCM_FORMAT_S32_BE:
		return AVTP_AAF_FORMAT_INT_32BIT;
	case SND_PCM_FORMAT_FLOAT_BE:
		return AVTP_AAF_FORMAT_FLOAT_32BIT;
	default:
		return AVTP_AAF_FORMAT_USER;
	}
}

static unsigned int alsa_to_avtp_rate(unsigned int rate)
{
	switch (rate) {
	case 8000:
		return AVTP_AAF_PCM_NSR_8KHZ;
	case 16000:
		return AVTP_AAF_PCM_NSR_16KHZ;
	case 24000:
		return AVTP_AAF_PCM_NSR_24KHZ;
	case 32000:
		return AVTP_AAF_PCM_NSR_32KHZ;
	case 44100:
		return AVTP_AAF_PCM_NSR_44_1KHZ;
	case 48000:
		return AVTP_AAF_PCM_NSR_48KHZ;
	case 88200:
		return AVTP_AAF_PCM_NSR_88_2KHZ;
	case 96000:
		return AVTP_AAF_PCM_NSR_96KHZ;
	case 176400:
		return AVTP_AAF_PCM_NSR_176_4KHZ;
	case 192000:
		return AVTP_AAF_PCM_NSR_192KHZ;
	default:
		return AVTP_AAF_PCM_NSR_USER;
	}
}

static int aaf_load_config(snd_pcm_aaf_t *aaf, snd_config_t *conf)
{
	snd_config_iterator_t cur, next;

	snd_config_for_each(cur, next, conf) {
		snd_config_t *entry = snd_config_iterator_entry(cur);
		const char *id;

		if (snd_config_get_id(entry, &id) < 0)
			goto err;

		if (strcmp(id, "comment") == 0 ||
		    strcmp(id, "type") == 0 ||
		    strcmp(id, "hint") == 0)
			continue;

		if (strcmp(id, "ifname") == 0) {
			const char *ifname;

			if (snd_config_get_string(entry, &ifname) < 0)
				goto err;

			snprintf(aaf->ifname, sizeof(aaf->ifname), "%s",
				 ifname);
		} else if (strcmp(id, "addr") == 0) {
			const char *addr;
			int n;

			if (snd_config_get_string(entry, &addr) < 0)
				goto err;

			n = sscanf(addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				   &aaf->addr[0], &aaf->addr[1],
				   &aaf->addr[2], &aaf->addr[3],
				   &aaf->addr[4], &aaf->addr[5]);
			if (n != 6)
				goto err;
		} else if (strcmp(id, "prio") == 0) {
			long prio;

			if (snd_config_get_integer(entry, &prio) < 0)
				goto err;

			if (prio < 0)
				goto err;

			aaf->prio = prio;
		} else if (strcmp(id, "streamid") == 0) {
			const char *streamid;
			int n;
			uint64_t buf[7];

			if (snd_config_get_string(entry, &streamid) < 0)
				goto err;

			n = sscanf(streamid, "%lx:%lx:%lx:%lx:%lx:%lx:%lx",
				   &buf[0], &buf[1], &buf[2], &buf[3],
				   &buf[4], &buf[5], &buf[6]);
			if (n != 7)
				goto err;

			aaf->streamid = buf[0] << 56 | buf[1] << 48 |
					buf[2] << 40 | buf[3] << 32 |
					buf[4] << 24 | buf[5] << 16 |
					buf[6];
		} else if (strcmp(id, "mtt") == 0) {
			long mtt;

			if (snd_config_get_integer(entry, &mtt) < 0)
				goto err;

			if (mtt < 0)
				goto err;

			aaf->mtt = mtt * NSEC_PER_USEC;
		} else if (strcmp(id, "time_uncertainty") == 0) {
			long t_uncertainty;

			if (snd_config_get_integer(entry, &t_uncertainty) < 0)
				goto err;

			if (t_uncertainty < 0)
				goto err;

			aaf->t_uncertainty = t_uncertainty * NSEC_PER_USEC;
		} else if (strcmp(id, "frames_per_pkt") == 0) {
			long frames_per_pkt;

			if (snd_config_get_integer(entry, &frames_per_pkt) < 0)
				goto err;

			if (frames_per_pkt < 0)
				goto err;

			aaf->frames_per_pkt = frames_per_pkt;
		} else {
			SNDERR("Invalid configuration: %s", id);
			goto err;
		}
	}

	return 0;

err:
	SNDERR("Error loading device configuration");
	return -EINVAL;
}

static int aaf_init_socket(snd_pcm_aaf_t *aaf)
{
	int fd, res;
	struct ifreq req;
	snd_pcm_ioplug_t *io = &aaf->io;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
	if (fd < 0) {
		SNDERR("Failed to open AF_PACKET socket");
		return -errno;
	}

	snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", aaf->ifname);
	res = ioctl(fd, SIOCGIFINDEX, &req);
	if (res < 0) {
		SNDERR("Failed to get network interface index");
		res = -errno;
		goto err;
	}

	aaf->sk_addr.sll_family = AF_PACKET;
	aaf->sk_addr.sll_protocol = htons(ETH_P_TSN);
	aaf->sk_addr.sll_halen = ETH_ALEN;
	aaf->sk_addr.sll_ifindex = req.ifr_ifindex;
	memcpy(&aaf->sk_addr.sll_addr, aaf->addr, ETH_ALEN);

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		res = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &aaf->prio,
				 sizeof(aaf->prio));
		if (res < 0) {
			SNDERR("Failed to set socket priority");
			res = -errno;
			goto err;
		}
	} else {
		/* TODO: Implement Capture mode support. */
		return -ENOTSUP;
	}

	aaf->sk_fd = fd;
	return 0;

err:
	close(fd);
	return res;
}

static int aaf_init_timer(snd_pcm_aaf_t *aaf)
{
	int fd;

	fd = timerfd_create(CLOCK_REF, 0);
	if (fd < 0)
		return -errno;

	aaf->timer_fd = fd;
	return 0;
}

static int aaf_init_pdu(snd_pcm_aaf_t *aaf)
{
	int res;
	struct avtp_stream_pdu *pdu;
	ssize_t frame_size, payload_size, pdu_size;
	snd_pcm_ioplug_t *io = &aaf->io;

	frame_size = snd_pcm_format_size(io->format, io->channels);
	if (frame_size < 0)
		return frame_size;

	payload_size = frame_size * aaf->frames_per_pkt;
	pdu_size = sizeof(*pdu) + payload_size;
	pdu = calloc(1, pdu_size);
	if (!pdu)
		return -ENOMEM;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		res = avtp_aaf_pdu_init(pdu);
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_TV, 1);
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_STREAM_ID,
				       aaf->streamid);
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_FORMAT,
				       alsa_to_avtp_format(io->format));
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_NSR,
				       alsa_to_avtp_rate(io->rate));
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_CHAN_PER_FRAME,
				       io->channels);
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_BIT_DEPTH,
				       snd_pcm_format_width(io->format));
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_STREAM_DATA_LEN,
				       payload_size);
		if (res < 0)
			goto err;

		res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_SP,
				       AVTP_AAF_PCM_SP_NORMAL);
		if (res < 0)
			goto err;
	}

	aaf->pdu = pdu;
	aaf->pdu_size = pdu_size;
	aaf->pdu_seq = 0;
	return 0;

err:
	free(pdu);
	return res;
}

static int aaf_init_audio_buffer(snd_pcm_aaf_t *aaf)
{
	char *audiobuf;
	ssize_t frame_size, audiobuf_size;
	snd_pcm_ioplug_t *io = &aaf->io;

	frame_size = snd_pcm_format_size(io->format, io->channels);
	if (frame_size < 0)
		return frame_size;

	audiobuf_size = frame_size * aaf->buffer_size;
	audiobuf = calloc(1, audiobuf_size);
	if (!audiobuf)
		return -ENOMEM;

	aaf->audiobuf = audiobuf;
	return 0;
}

static int aaf_init_areas(snd_pcm_aaf_t *aaf)
{
	snd_pcm_channel_area_t *audiobuf_areas, *payload_areas;
	ssize_t sample_size, frame_size;
	snd_pcm_ioplug_t *io = &aaf->io;

	sample_size = snd_pcm_format_size(io->format, 1);
	if (sample_size < 0)
		return sample_size;

	frame_size = sample_size * io->channels;

	audiobuf_areas = calloc(io->channels, sizeof(snd_pcm_channel_area_t));
	if (!audiobuf_areas)
		return -ENOMEM;

	payload_areas = calloc(io->channels, sizeof(snd_pcm_channel_area_t));
	if (!payload_areas) {
		free(audiobuf_areas);
		return -ENOMEM;
	}

	for (unsigned int i = 0; i < io->channels; i++) {
		audiobuf_areas[i].addr = aaf->audiobuf;
		audiobuf_areas[i].first = i * sample_size * 8;
		audiobuf_areas[i].step = frame_size * 8;

		payload_areas[i].addr = aaf->pdu->avtp_payload;
		payload_areas[i].first = i * sample_size * 8;
		payload_areas[i].step = frame_size * 8;
	}

	aaf->audiobuf_areas = audiobuf_areas;
	aaf->payload_areas = payload_areas;
	return 0;
}

static void aaf_inc_hw_ptr(snd_pcm_aaf_t *aaf, snd_pcm_sframes_t val)
{
	aaf->hw_ptr += val;

	if (aaf->hw_ptr >= aaf->boundary)
		aaf->hw_ptr -= aaf->boundary;
}

static int aaf_mclk_start_playback(snd_pcm_aaf_t *aaf)
{
	int res;
	struct timespec now;
	struct itimerspec itspec;
	snd_pcm_ioplug_t *io = &aaf->io;

	res = clock_gettime(CLOCK_REF, &now);
	if (res < 0) {
		SNDERR("Failed to get time from clock");
		return -errno;
	}

	aaf->mclk_period = (NSEC_PER_SEC * aaf->frames_per_pkt) / io->rate;
	aaf->mclk_ticks = 0;
	aaf->mclk_start_time = now.tv_sec * NSEC_PER_SEC + now.tv_nsec +
			       aaf->mclk_period;

	itspec.it_value.tv_sec = aaf->mclk_start_time / NSEC_PER_SEC;
	itspec.it_value.tv_nsec = aaf->mclk_start_time % NSEC_PER_SEC;
	itspec.it_interval.tv_sec = 0;
	itspec.it_interval.tv_nsec = aaf->mclk_period;
	res = timerfd_settime(aaf->timer_fd, TFD_TIMER_ABSTIME, &itspec, NULL);
	if (res < 0)
		return -errno;

	return 0;
}

static int aaf_mclk_reset(snd_pcm_aaf_t *aaf)
{
	aaf->mclk_start_time = 0;
	aaf->mclk_period = 0;
	aaf->mclk_ticks = 0;

	if (aaf->timer_fd != -1) {
		int res;
		struct itimerspec itspec = { 0 };

		res = timerfd_settime(aaf->timer_fd, 0, &itspec, NULL);
		if (res < 0) {
			SNDERR("Failed to stop media clock");
			return res;
		}
	}

	return 0;
}

static uint64_t aaf_mclk_gettime(snd_pcm_aaf_t *aaf)
{
	return aaf->mclk_start_time + aaf->mclk_period * aaf->mclk_ticks;
}

static int aaf_tx_pdu(snd_pcm_aaf_t *aaf)
{
	int res;
	uint64_t ptime;
	snd_pcm_sframes_t n;
	snd_pcm_ioplug_t *io = &aaf->io;
	snd_pcm_t *pcm = io->pcm;
	struct avtp_stream_pdu *pdu = aaf->pdu;

	n = aaf->buffer_size - snd_pcm_avail(pcm);
	if (n == 0) {
		/* If there is no data in audio buffer to be transmitted,
		 * we reached an underrun state.
		 */
		return -EPIPE;
	}
	if (n < aaf->frames_per_pkt) {
		/* If there isn't enough frames to fill the AVTP packet, we
		 * drop them. This behavior is suggested by IEEE 1722-2016
		 * spec, section 7.3.5.
		 */
		aaf_inc_hw_ptr(aaf, n);
		return 0;
	}

	res = snd_pcm_areas_copy_wrap(aaf->payload_areas, 0,
				      aaf->frames_per_pkt,
				      aaf->audiobuf_areas,
				      aaf->hw_ptr % aaf->buffer_size,
				      aaf->buffer_size, io->channels,
				      aaf->frames_per_pkt, io->format);
	if (res < 0) {
		SNDERR("Failed to copy data to AVTP payload");
		return res;
	}

	res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_SEQ_NUM, aaf->pdu_seq++);
	if (res < 0)
		return res;

	ptime = aaf_mclk_gettime(aaf) + aaf->mtt + aaf->t_uncertainty;
	res = avtp_aaf_pdu_set(pdu, AVTP_AAF_FIELD_TIMESTAMP, ptime);
	if (res < 0)
		return res;

	n = sendto(aaf->sk_fd, aaf->pdu, aaf->pdu_size, 0,
		   (struct sockaddr *) &aaf->sk_addr,
		   sizeof(aaf->sk_addr));
	if (n < 0 || n != aaf->pdu_size) {
		SNDERR("Failed to send AAF PDU");
		return -EIO;
	}

	aaf_inc_hw_ptr(aaf, aaf->frames_per_pkt);
	return 0;
}

static int aaf_mclk_timeout_playback(snd_pcm_aaf_t *aaf)
{
	int res;
	ssize_t n;
	uint64_t expirations;

	n = read(aaf->timer_fd, &expirations, sizeof(uint64_t));
	if (n < 0) {
		SNDERR("Failed to read() timer");
		return -errno;
	}

	if (expirations != 1)
		pr_debug("Missed %llu tx interval(s) ", expirations - 1);

	while (expirations--) {
		res = aaf_tx_pdu(aaf);
		if (res < 0)
			return res;
		aaf->mclk_ticks++;
	}

	return 0;
}

static int aaf_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	if (!aaf)
		return -EBADFD;

	free(aaf);
	aaf = NULL;
	return 0;
}

static int aaf_hw_params(snd_pcm_ioplug_t *io,
			 snd_pcm_hw_params_t *params ATTRIBUTE_UNUSED)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	if (io->access != SND_PCM_ACCESS_RW_INTERLEAVED)
		return -ENOTSUP;

	if (io->buffer_size > LONG_MAX)
		return -EINVAL;

	/* XXX: We might want to support Little Endian format in future. To
	 * achieve that, we need to convert LE samples to BE before
	 * transmitting them.
	 */
	switch (io->format) {
	case SND_PCM_FORMAT_S16_BE:
	case SND_PCM_FORMAT_S24_3BE:
	case SND_PCM_FORMAT_S32_BE:
	case SND_PCM_FORMAT_FLOAT_BE:
		break;
	default:
		return -ENOTSUP;
	}

	switch (io->rate) {
	case 8000:
	case 16000:
	case 24000:
	case 32000:
	case 44100:
	case 48000:
	case 88200:
	case 96000:
	case 176400:
	case 192000:
		break;
	default:
		return -ENOTSUP;
	}

	aaf->buffer_size = io->buffer_size;

	res = aaf_init_pdu(aaf);
	if (res < 0)
		return res;

	res = aaf_init_audio_buffer(aaf);
	if (res < 0)
		goto err_free_pdu;

	res = aaf_init_areas(aaf);
	if (res < 0)
		goto err_free_audiobuf;

	return 0;

err_free_audiobuf:
	free(aaf->audiobuf);
err_free_pdu:
	free(aaf->pdu);
	return res;
}

static int aaf_hw_free(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	free(aaf->audiobuf_areas);
	free(aaf->payload_areas);
	free(aaf->audiobuf);
	free(aaf->pdu);
	return 0;
}

static int aaf_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params)
{
	int res;
	snd_pcm_uframes_t boundary;
	snd_pcm_aaf_t *aaf = io->private_data;

	res = snd_pcm_sw_params_get_boundary(params, &boundary);
	if (res < 0)
		return res;

	if (boundary > LONG_MAX)
		return -EINVAL;

	aaf->boundary = boundary;
	return 0;
}

static snd_pcm_sframes_t aaf_pointer(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	return aaf->hw_ptr;
}

static int aaf_poll_descriptors_count(snd_pcm_ioplug_t *io ATTRIBUTE_UNUSED)
{
	if (io->stream == SND_PCM_STREAM_PLAYBACK)
		return FD_COUNT_PLAYBACK;
	else
		return -ENOTSUP;
}

static int aaf_poll_descriptors(snd_pcm_ioplug_t *io, struct pollfd *pfd,
				unsigned int space)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		if (space != FD_COUNT_PLAYBACK)
			return -EINVAL;

		pfd[0].fd = aaf->timer_fd;
		pfd[0].events = POLLIN;
	} else {
		/* TODO: Implement Capture mode support. */
		return -ENOTSUP;
	}

	return space;
}

static int aaf_poll_revents(snd_pcm_ioplug_t *io, struct pollfd *pfd,
			    unsigned int nfds, unsigned short *revents)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		if (nfds != FD_COUNT_PLAYBACK)
			return -EINVAL;

		if (pfd[0].revents & POLLIN) {
			res = aaf_mclk_timeout_playback(aaf);
			if (res < 0)
				return res;

			*revents = POLLIN;
		}
	} else {
		/* TODO: Implement Capture mode support. */
		return -ENOTSUP;
	}

	return 0;
}

static int aaf_prepare(snd_pcm_ioplug_t *io)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	aaf->hw_ptr = 0;
	res = aaf_mclk_reset(aaf);
	if (res < 0)
		return res;

	return 0;
}

static int aaf_start(snd_pcm_ioplug_t *io)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	res = aaf_init_socket(aaf);
	if (res < 0)
		return res;

	res = aaf_init_timer(aaf);
	if (res < 0)
		goto err_close_sk;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		res = aaf_mclk_start_playback(aaf);
		if (res < 0)
			goto err_close_timer;
	}

	return 0;

err_close_timer:
	close(aaf->timer_fd);
err_close_sk:
	close(aaf->sk_fd);
	return res;
}

static int aaf_stop(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	close(aaf->timer_fd);
	close(aaf->sk_fd);
	return 0;
}

static snd_pcm_sframes_t aaf_transfer(snd_pcm_ioplug_t *io,
				      const snd_pcm_channel_area_t *areas,
				      snd_pcm_uframes_t offset,
				      snd_pcm_uframes_t size)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		res = snd_pcm_areas_copy_wrap(aaf->audiobuf_areas,
					      (io->appl_ptr % aaf->buffer_size),
					      aaf->buffer_size, areas, offset,
					      size, io->channels, size,
					      io->format);
		if (res < 0)
			return res;
	} else {
		/* TODO: Implement Capture mode support. */
		return -ENOTSUP;
	}

	return size;
}

static const snd_pcm_ioplug_callback_t aaf_callback = {
	.close = aaf_close,
	.hw_params = aaf_hw_params,
	.hw_free = aaf_hw_free,
	.sw_params = aaf_sw_params,
	.pointer = aaf_pointer,
	.poll_descriptors_count = aaf_poll_descriptors_count,
	.poll_descriptors = aaf_poll_descriptors,
	.poll_revents = aaf_poll_revents,
	.prepare = aaf_prepare,
	.start = aaf_start,
	.stop = aaf_stop,
	.transfer = aaf_transfer,
};

SND_PCM_PLUGIN_DEFINE_FUNC(aaf)
{
	snd_pcm_aaf_t *aaf;
	int res;

	aaf = calloc(1, sizeof(*aaf));
	if (!aaf) {
		SNDERR("Failed to allocate memory");
		return -ENOMEM;
	}

	aaf->sk_fd = -1;
	aaf->timer_fd = -1;

	res = aaf_load_config(aaf, conf);
	if (res < 0)
		goto err;

	aaf->io.version = SND_PCM_IOPLUG_VERSION;
	aaf->io.name = "AVTP Audio Format (AAF) Plugin";
	aaf->io.callback = &aaf_callback;
	aaf->io.private_data = aaf;
	aaf->io.flags = SND_PCM_IOPLUG_FLAG_BOUNDARY_WA;
	res = snd_pcm_ioplug_create(&aaf->io, name, stream, mode);
	if (res < 0) {
		SNDERR("Failed to create ioplug instance");
		goto err;
	}

	*pcmp = aaf->io.pcm;
	return 0;

err:
	free(aaf);
	return res;
}

SND_PCM_PLUGIN_SYMBOL(aaf);
