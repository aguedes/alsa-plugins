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
#include <inttypes.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#ifdef AAF_DEBUG
#define pr_debug(...) SNDERR(__VA_ARGS__)
#else
#define pr_debug(...) (void)0
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#define NSEC_PER_USEC 1000
#define NSEC_PER_SEC  1000000000
#define TAI_OFFSET    (37ULL * NSEC_PER_SEC)
#define TAI_TO_UTC(t) (t - TAI_OFFSET)

#define FD_COUNT_PLAYBACK 1
#define FD_COUNT_CAPTURE  2

typedef struct {
	snd_pcm_ioplug_t io;

	char ifname[IFNAMSIZ];
	unsigned char addr[ETH_ALEN];
	int prio;
	uint64_t streamid;
	int mtt;
	int t_uncertainty;
	snd_pcm_uframes_t frames_per_pdu;

	int sk_fd;
	int timer_fd;

	struct sockaddr_ll sk_addr;

	struct avtp_stream_pdu *pdu;
	int pdu_size;
	uint8_t pdu_seq;
	uint64_t pdu_count;

	uint64_t mclk_start_time;
	uint64_t mclk_period;
	uint64_t mclk_ticks;

	const snd_pcm_channel_area_t *audiobuf_areas;
	snd_pcm_channel_area_t *payload_areas;

	snd_pcm_uframes_t hw_ptr;
	snd_pcm_uframes_t hw_virt_ptr;
	snd_pcm_uframes_t boundary;
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

static bool is_pdu_valid(struct avtp_stream_pdu *pdu, uint64_t streamid,
			 unsigned int data_len, unsigned int format,
			 unsigned int nsr, unsigned int channels,
			 unsigned int depth)
{
	int res;
	uint64_t val64;
	uint32_t val32;
	struct avtp_common_pdu *common = (struct avtp_common_pdu *) pdu;

	res = avtp_pdu_get(common, AVTP_FIELD_SUBTYPE, &val32);
	if (res < 0)
		return false;
	if (val32 != AVTP_SUBTYPE_AAF) {
		pr_debug("Subtype mismatch: expected %u, got %u",
			 AVTP_SUBTYPE_AAF, val32);
		return false;
	}

	res = avtp_pdu_get(common, AVTP_FIELD_VERSION, &val32);
	if (res < 0)
		return false;
	if (val32 != 0) {
		pr_debug("Version mismatch: expected %u, got %u", 0, val32);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_STREAM_ID, &val64);
	if (res < 0)
		return false;
	if (val64 != streamid) {
		pr_debug("Streamid mismatch: expected %lu, got %lu", streamid,
			 val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_TV, &val64);
	if (res < 0)
		return false;
	if (val64 != 1) {
		pr_debug("TV mismatch: expected %u, got %lu", 1, val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_SP, &val64);
	if (res < 0)
		return false;
	if (val64 != AVTP_AAF_PCM_SP_NORMAL) {
		pr_debug("SP mismatch: expected %u, got %lu",
			 AVTP_AAF_PCM_SP_NORMAL, val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_FORMAT, &val64);
	if (res < 0)
		return false;
	if (val64 != format) {
		pr_debug("Format mismatch: expected %u, got %lu", format,
			 val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_NSR, &val64);
	if (res < 0)
		return false;
	if (val64 != nsr) {
		pr_debug("NSR mismatch: expected %u, got %lu", nsr, val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_CHAN_PER_FRAME, &val64);
	if (res < 0)
		return false;
	if (val64 != channels) {
		pr_debug("Channels mismatch: expected %u, got %lu", channels,
			 val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_BIT_DEPTH, &val64);
	if (res < 0)
		return false;
	if (val64 != depth) {
		pr_debug("Bit depth mismatch: expected %u, got %lu", depth,
			 val64);
		return false;
	}

	res = avtp_aaf_pdu_get(pdu, AVTP_AAF_FIELD_STREAM_DATA_LEN, &val64);
	if (res < 0)
		return false;
	if (val64 != data_len) {
		pr_debug("Data len mismatch: expected %u, got %lu",
			 data_len, val64);
		return false;
	}

	return true;
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
			unsigned char addr[6];
			unsigned short unique_id;
			int n;

			if (snd_config_get_string(entry, &streamid) < 0)
				goto err;

			n = sscanf(streamid,
				   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hx",
				   &addr[0], &addr[1], &addr[2], &addr[3],
				   &addr[4], &addr[5], &unique_id);
			if (n != 7)
				goto err;

			aaf->streamid = (uint64_t) addr[0] << 56 |
					(uint64_t) addr[1] << 48 |
					(uint64_t) addr[2] << 40 |
					(uint64_t) addr[3] << 32 |
					(uint64_t) addr[4] << 24 |
					(uint64_t) addr[5] << 16 |
					unique_id;
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
		} else if (strcmp(id, "frames_per_pdu") == 0) {
			long frames_per_pdu;

			if (snd_config_get_integer(entry, &frames_per_pdu) < 0)
				goto err;

			if (frames_per_pdu < 0)
				goto err;

			aaf->frames_per_pdu = frames_per_pdu;
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

	fd = socket(AF_PACKET, SOCK_DGRAM|SOCK_NONBLOCK, htons(ETH_P_TSN));
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
		struct packet_mreq mreq = { 0 };

		res = bind(fd, (struct sockaddr *) &aaf->sk_addr,
			   sizeof(aaf->sk_addr));
		if (res < 0) {
			SNDERR("Failed to bind socket");
			res = -errno;
			goto err;
		}

		mreq.mr_ifindex = req.ifr_ifindex;
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		memcpy(&mreq.mr_address, aaf->addr, ETH_ALEN);
		res = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				 &mreq, sizeof(struct packet_mreq));
		if (res < 0) {
			SNDERR("Failed to add multicast address");
			res = -errno;
			goto err;
		}
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

	fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
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

	payload_size = frame_size * aaf->frames_per_pdu;
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
	return 0;

err:
	free(pdu);
	return res;
}

static int aaf_init_areas(snd_pcm_aaf_t *aaf, snd_pcm_channel_area_t *areas,
			  void *buf)
{
	ssize_t sample_size, frame_size;
	snd_pcm_ioplug_t *io = &aaf->io;

	sample_size = snd_pcm_format_size(io->format, 1);
	if (sample_size < 0)
		return sample_size;

	frame_size = sample_size * io->channels;

	for (unsigned int i = 0; i < io->channels; i++) {
		areas[i].addr = buf;
		areas[i].first = i * sample_size * 8;
		areas[i].step = frame_size * 8;
	}

	return 0;
}

static int aaf_init_payload_areas(snd_pcm_aaf_t *aaf)
{
	int res;
	snd_pcm_channel_area_t *areas;
	snd_pcm_ioplug_t *io = &aaf->io;

	areas = calloc(io->channels, sizeof(snd_pcm_channel_area_t));
	if (!areas)
		return -ENOMEM;

	res = aaf_init_areas(aaf, areas, aaf->pdu->avtp_payload);
	if (res < 0)
		goto err;

	aaf->payload_areas = areas;
	return 0;

err:
	free(areas);
	return res;
}

static void aaf_inc_ptr(snd_pcm_uframes_t *ptr, snd_pcm_uframes_t val,
			snd_pcm_uframes_t boundary)
{
	*ptr += val;

	if (*ptr > boundary)
		*ptr -= boundary;
}

static int aaf_mclk_start_playback(snd_pcm_aaf_t *aaf)
{
	int res;
	struct timespec now;
	struct itimerspec itspec;
	uint64_t time_utc;
	snd_pcm_ioplug_t *io = &aaf->io;

	res = clock_gettime(CLOCK_TAI, &now);
	if (res < 0) {
		SNDERR("Failed to get time from clock");
		return -errno;
	}

	aaf->mclk_period = (uint64_t)NSEC_PER_SEC * aaf->frames_per_pdu /
			   io->rate;
	aaf->mclk_ticks = 0;
	aaf->mclk_start_time = now.tv_sec * NSEC_PER_SEC + now.tv_nsec +
			       aaf->mclk_period;

	time_utc = TAI_TO_UTC(aaf->mclk_start_time);
	itspec.it_value.tv_sec = time_utc / NSEC_PER_SEC;
	itspec.it_value.tv_nsec = time_utc % NSEC_PER_SEC;
	itspec.it_interval.tv_sec = 0;
	itspec.it_interval.tv_nsec = aaf->mclk_period;
	res = timerfd_settime(aaf->timer_fd, TFD_TIMER_ABSTIME, &itspec, NULL);
	if (res < 0)
		return -errno;

	return 0;
}

static int aaf_mclk_start_capture(snd_pcm_aaf_t *aaf, uint32_t avtp_time)
{
	int res;
	struct timespec tspec;
	struct itimerspec itspec;
	uint64_t ptime, now, time_utc;
	snd_pcm_ioplug_t *io = &aaf->io;

	res = clock_gettime(CLOCK_TAI, &tspec);
	if (res < 0) {
		SNDERR("Failed to get time from clock");
		return -errno;
	}

	now = (uint64_t)tspec.tv_sec * NSEC_PER_SEC + tspec.tv_nsec;

	/* The avtp_timestamp within AAF packet is the lower part (32
	 * less-significant bits) from presentation time calculated by the
	 * talker.
	 */
	ptime = (now & 0xFFFFFFFF00000000ULL) | avtp_time;

	/* If 'ptime' is less than the 'now', it means the higher part
	 * from 'ptime' needs to be incremented by 1 in order to recover the
	 * presentation time set by the talker.
	 */
	if (ptime < now)
		ptime += (1ULL << 32);

	aaf->mclk_period = (uint64_t)NSEC_PER_SEC * aaf->frames_per_pdu /
			   io->rate;
	aaf->mclk_ticks = 0;
	aaf->mclk_start_time = ptime;

	time_utc = TAI_TO_UTC(ptime);
	itspec.it_value.tv_sec = time_utc / NSEC_PER_SEC;
	itspec.it_value.tv_nsec = time_utc % NSEC_PER_SEC;
	itspec.it_interval.tv_sec = 0;
	itspec.it_interval.tv_nsec = aaf->mclk_period;
	res = timerfd_settime(aaf->timer_fd, TFD_TIMER_ABSTIME, &itspec, NULL);
	if (res < 0) {
		SNDERR("Failed to set timer");
		return -errno;
	}

	return 0;
}

static int aaf_mclk_reset(snd_pcm_aaf_t *aaf)
{
	int res;
	struct itimerspec itspec = { 0 };

	res = timerfd_settime(aaf->timer_fd, 0, &itspec, NULL);
	if (res < 0) {
		SNDERR("Failed to stop media clock");
		return res;
	}

	aaf->mclk_start_time = 0;
	aaf->mclk_period = 0;
	aaf->mclk_ticks = 0;
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
	ssize_t n;
	snd_pcm_uframes_t hw_avail;
	snd_pcm_ioplug_t *io = &aaf->io;
	struct avtp_stream_pdu *pdu = aaf->pdu;

	hw_avail = snd_pcm_ioplug_hw_avail(io, aaf->hw_ptr, io->appl_ptr);
	if (hw_avail == 0) {
		/* If there is no frames available for transmission, we reached
		 * an underrun state.
		 */
		return -EPIPE;
	}
	if (hw_avail < aaf->frames_per_pdu) {
		/* If there isn't enough frames to fill the AVTPDU, we drop
		 * them. This behavior is suggested by IEEE 1722-2016 spec,
		 * section 7.3.5.
		 */
		aaf_inc_ptr(&aaf->hw_ptr, hw_avail, aaf->boundary);
		return 0;
	}

	res = snd_pcm_areas_copy_wrap(aaf->payload_areas, 0,
				      aaf->frames_per_pdu,
				      aaf->audiobuf_areas,
				      (aaf->hw_ptr % io->buffer_size),
				      io->buffer_size, io->channels,
				      aaf->frames_per_pdu, io->format);
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

	aaf_inc_ptr(&aaf->hw_ptr, aaf->frames_per_pdu, aaf->boundary);
	return 0;
}

static int aaf_rx_pdu(snd_pcm_aaf_t *aaf)
{
	int res;
	ssize_t n;
	uint64_t seq, avtp_time;
	snd_pcm_uframes_t hw_avail;
	snd_pcm_ioplug_t *io = &aaf->io;
	snd_pcm_t *pcm = io->pcm;

	n = recv(aaf->sk_fd, aaf->pdu, aaf->pdu_size, 0);
	if (n < 0 || n != aaf->pdu_size) {
		SNDERR("Failed to receive data");
		return -EIO;
	}

	if (io->state == SND_PCM_STATE_DRAINING) {
		/* If device is in DRAIN state, we shouldn't copy any more data
		 * to audio buffer. So we are done here.
		 */
		return 0;
	}

	if (!is_pdu_valid(aaf->pdu, aaf->streamid,
			  snd_pcm_frames_to_bytes(pcm, aaf->frames_per_pdu),
			  alsa_to_avtp_format(io->format),
			  alsa_to_avtp_rate(io->rate),
			  io->channels, snd_pcm_format_width(io->format)))
		return 0;

	res = avtp_aaf_pdu_get(aaf->pdu, AVTP_AAF_FIELD_SEQ_NUM, &seq);
	if (res < 0)
		return res;
	if (seq != aaf->pdu_seq) {
		pr_debug("Sequence mismatch: expected %u, got %lu",
			 aaf->pdu_seq, seq);
		aaf->pdu_seq = seq;
	}
	aaf->pdu_seq++;

	res = avtp_aaf_pdu_get(aaf->pdu, AVTP_AAF_FIELD_TIMESTAMP, &avtp_time);
	if (res < 0)
		return res;

	if (aaf->mclk_start_time == 0) {
		res = aaf_mclk_start_capture(aaf, avtp_time);
		if (res < 0)
			return res;
	} else {
		uint64_t ptime = aaf->mclk_start_time + aaf->mclk_period *
				 aaf->pdu_count;

		if (avtp_time != ptime % (1ULL << 32)) {
			pr_debug("Packet dropped: PT not expected");
			return 0;
		}
		if (ptime < aaf_mclk_gettime(aaf)) {
			pr_debug("Packet dropped: PT in the past");
			return 0;
		}
	}

	hw_avail = snd_pcm_ioplug_hw_avail(io, aaf->hw_virt_ptr, io->appl_ptr);
	if (hw_avail < aaf->frames_per_pdu) {
		/* If there isn't enough space available on buffer to copy the
		 * samples from AVTPDU, it means we've reached an overrun
		 * state.
		 */
		return -EPIPE;
	}

	res = snd_pcm_areas_copy_wrap(aaf->audiobuf_areas,
				      (aaf->hw_virt_ptr % io->buffer_size),
				      io->buffer_size, aaf->payload_areas,
				      0, aaf->frames_per_pdu, io->channels,
				      aaf->frames_per_pdu, io->format);
	if (res < 0) {
		SNDERR("Failed to copy data from AVTP payload");
		return res;
	}

	aaf->pdu_count++;
	aaf_inc_ptr(&aaf->hw_virt_ptr, aaf->frames_per_pdu, aaf->boundary);
	return 0;
}

static int aaf_flush_rx_buf(snd_pcm_aaf_t *aaf)
{
	char *tmp;
	ssize_t n;

	tmp = malloc(aaf->pdu_size);
	if (!tmp)
		return -ENOMEM;

	do {
		n = recv(aaf->sk_fd, tmp, aaf->pdu_size, 0);
	} while (n != -1);

	if (errno != EAGAIN && errno != EWOULDBLOCK) {
		/* Something unexpected has happened while flushing the socket
		 * rx buffer so we return error.
		 */
		free(tmp);
		return -errno;
	}

	free(tmp);
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

static int aaf_mclk_timeout_capture(snd_pcm_aaf_t *aaf)
{
	ssize_t n;
	uint64_t expirations;
	snd_pcm_ioplug_t *io = &aaf->io;

	n = read(aaf->timer_fd, &expirations, sizeof(uint64_t));
	if (n < 0) {
		SNDERR("Failed to read() timer");
		return -errno;
	}

	if (expirations != 1)
		pr_debug("Missed %llu presentation time(s) ", expirations - 1);

	while (expirations--) {
		snd_pcm_sframes_t len = aaf->hw_virt_ptr - aaf->hw_ptr;
		if (len < 0)
			len += aaf->boundary;

		if ((snd_pcm_uframes_t) len > io->buffer_size) {
			/* If the distance between hw virtual pointer and hw
			 * pointer is greater than the buffer size, it means we
			 * had an overrun error so -EPIPE is returned.
			 */
			return -EPIPE;
		}

		aaf_inc_ptr(&aaf->hw_ptr, aaf->frames_per_pdu, aaf->boundary);
		aaf->mclk_ticks++;
	}

	return 0;
}

static int aaf_set_hw_constraint(snd_pcm_aaf_t *aaf)
{
	int res;
	snd_pcm_ioplug_t *io = &aaf->io;
	const unsigned int accesses[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		SND_PCM_ACCESS_MMAP_INTERLEAVED,
	};
	const unsigned int formats[] = {
		SND_PCM_FORMAT_S16_BE,
		SND_PCM_FORMAT_S24_3BE,
		SND_PCM_FORMAT_S32_BE,
		SND_PCM_FORMAT_FLOAT_BE,
	};
	const unsigned int rates[] = {
		8000,
		16000,
		24000,
		32000,
		44100,
		48000,
		88200,
		96000,
		176400,
		192000,
	};

	res = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					    ARRAY_SIZE(accesses), accesses);
	if (res < 0)
		return res;

	res = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					    ARRAY_SIZE(formats), formats);
	if (res < 0)
		return res;

	res = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_RATE,
					    ARRAY_SIZE(rates), rates);
	if (res < 0)
		return res;

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

static void aaf_dump(snd_pcm_ioplug_t *io, snd_output_t *out)
{
	snd_pcm_aaf_t *aaf = io->private_data;
	snd_pcm_t *pcm = io->pcm;

	snd_output_printf(out, "%s\n", io->name);
	snd_output_printf(out, "PCM setup is:\n");
	snd_pcm_dump_setup(pcm, out);
	snd_output_printf(out, "AVTP setup is:\n");
	snd_output_printf(out, "  ifname: %s\n", aaf->ifname);
	snd_output_printf(out, "  macaddr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
			  aaf->addr[0], aaf->addr[1], aaf->addr[2],
			  aaf->addr[3], aaf->addr[4], aaf->addr[5]);
	snd_output_printf(out, "  priority: %d\n", aaf->prio);
	snd_output_printf(out, "  streamid: %"PRIX64"\n", aaf->streamid);
	snd_output_printf(out, "  mtt: %d\n", aaf->mtt / NSEC_PER_USEC);
	snd_output_printf(out, "  time uncertainty: %d\n",
			  aaf->t_uncertainty / NSEC_PER_USEC);
	snd_output_printf(out, "  frame per AVTPDU: %lu\n",
			  aaf->frames_per_pdu);
}

static int aaf_hw_params(snd_pcm_ioplug_t *io,
			 snd_pcm_hw_params_t *params ATTRIBUTE_UNUSED)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	res = aaf_init_socket(aaf);
	if (res < 0)
		return res;

	res = aaf_init_timer(aaf);
	if (res < 0)
		goto err_close_sk;

	res = aaf_init_pdu(aaf);
	if (res < 0)
		goto err_close_timer;

	res = aaf_init_payload_areas(aaf);
	if (res < 0)
		goto err_free_pdu;

	return 0;

err_free_pdu:
	free(aaf->pdu);
err_close_timer:
	close(aaf->timer_fd);
err_close_sk:
	close(aaf->sk_fd);
	return res;
}

static int aaf_hw_free(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	close(aaf->sk_fd);
	close(aaf->timer_fd);
	free(aaf->pdu);
	free(aaf->payload_areas);
	return 0;
}

static int aaf_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	res = snd_pcm_sw_params_get_boundary(params, &aaf->boundary);
	if (res < 0)
		return res;

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
		return FD_COUNT_CAPTURE;
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
		if (space != FD_COUNT_CAPTURE)
			return -EINVAL;

		pfd[0].fd = aaf->timer_fd;
		pfd[0].events = POLLIN;
		pfd[1].fd = aaf->sk_fd;
		pfd[1].events = POLLIN;
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
		if (nfds != FD_COUNT_CAPTURE)
			return -EINVAL;

		if (pfd[0].revents & POLLIN) {
			res = aaf_mclk_timeout_capture(aaf);
			if (res < 0)
				return res;

			*revents = POLLIN;
		}

		if (pfd[1].revents & POLLIN) {
			res = aaf_rx_pdu(aaf);
			if (res < 0)
				return res;
		}
	}

	return 0;
}

static int aaf_prepare(snd_pcm_ioplug_t *io)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	aaf->audiobuf_areas = snd_pcm_ioplug_mmap_areas(io);
	aaf->pdu_seq = 0;
	aaf->pdu_count = 0;
	aaf->hw_ptr = 0;
	aaf->hw_virt_ptr = 0;

	res = aaf_mclk_reset(aaf);
	if (res < 0)
		return res;

	return 0;
}

static int aaf_start(snd_pcm_ioplug_t *io)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		res = aaf_mclk_start_playback(aaf);
	} else {
		/* Discard any packet on socket buffer to ensure the plugin
		 * process only packets that arrived after the device has
		 * started.
		 */
		res = aaf_flush_rx_buf(aaf);
	}

	if (res < 0)
		return res;

	return 0;
}

static int aaf_stop(snd_pcm_ioplug_t *io)
{
	int res;
	snd_pcm_aaf_t *aaf = io->private_data;

	res = aaf_mclk_reset(aaf);
	if (res < 0)
		return res;

	return 0;
}

static const snd_pcm_ioplug_callback_t aaf_callback = {
	.close = aaf_close,
	.dump = aaf_dump,
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
	aaf->io.mmap_rw = 1;
	res = snd_pcm_ioplug_create(&aaf->io, name, stream, mode);
	if (res < 0) {
		SNDERR("Failed to create ioplug instance");
		goto err;
	}

	res = aaf_set_hw_constraint(aaf);
	if (res < 0) {
		SNDERR("Failed to set hw constraints");
		snd_pcm_ioplug_delete(&aaf->io);
		goto err;
	}

	*pcmp = aaf->io.pcm;
	return 0;

err:
	free(aaf);
	return res;
}

SND_PCM_PLUGIN_SYMBOL(aaf);
