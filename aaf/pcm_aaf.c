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
#include <linux/if.h>
#include <linux/if_ether.h>
#include <string.h>
#include <stdint.h>

#define NSEC_PER_USEC		1000ULL

typedef struct {
	snd_pcm_ioplug_t io;

	char ifname[IFNAMSIZ];
	uint8_t addr[ETH_ALEN];
	int prio;
	uint64_t streamid;
	int mtt;
	int t_uncertainty;
	int frames_per_pkt;
} snd_pcm_aaf_t;

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

static int aaf_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_aaf_t *aaf = io->private_data;

	if (!aaf)
		return -EBADFD;

	free(aaf);
	aaf = NULL;
	return 0;
}

static snd_pcm_sframes_t aaf_pointer(snd_pcm_ioplug_t *io)
{
	return 0;
}

static int aaf_start(snd_pcm_ioplug_t *io)
{
	return 0;
}

static int aaf_stop(snd_pcm_ioplug_t *io)
{
	return 0;
}

static const snd_pcm_ioplug_callback_t aaf_callback = {
	.close = aaf_close,
	.pointer = aaf_pointer,
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

	res = aaf_load_config(aaf, conf);
	if (res < 0)
		goto err;

	aaf->io.version = SND_PCM_IOPLUG_VERSION;
	aaf->io.name = "AVTP Audio Format (AAF) Plugin";
	aaf->io.callback = &aaf_callback;
	aaf->io.private_data = aaf;
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
