/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <net/if.h> // For if_nametoindex
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <signal.h> // For detecting Ctrl-C
#include <sys/resource.h> // For setting rlmit

#include <limits.h>
#include <bpf/libbpf.h>

#include "clean-dns.h"
#include "clean-dns.kern.skel.h"

int usage(const char *progname)
{
    fprintf(stderr, "Usage: %s <ifname> [--unload]\n", progname);
    return 1;
}

static int set_rlimit(long int lim)
{
    struct rlimit rlim = {
    	.rlim_cur = lim,
        .rlim_max = lim,
    };

    return !setrlimit(RLIMIT_MEMLOCK, &rlim) ? 0 : -errno;
}

/*
 * Simple convenience wrapper around libbpf_strerror for which you don't have
 * to provide a buffer. Instead uses its own static buffer and returns a pointer
 * to it.
 *
 * This of course comes with the tradeoff that it is no longer thread safe and
 * later invocations overwrite previous results.
 */
static const char *get_libbpf_strerror(int err) {
    static char buf[200];
    libbpf_strerror(err, buf, sizeof(buf));
    return buf;
}


int main(int argc, char *argv[])
{
    int err = 0, i, _err, ingress_fd, egress_fd;
    int ifindex = 0;
    char pin_path[100];
    struct clean_dns_kern *skel = NULL;
    bool unload = false;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);

    // Detect if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return EXIT_FAILURE;
    }

    // Increase rlimit
    err = set_rlimit(RLIM_INFINITY);
    if (err) {
        fprintf(stderr, "Could not set rlimit to infinity: %s\n",
                get_libbpf_strerror(err));
        return EXIT_FAILURE;
    }


    if (argc < 2)
        return usage(argv[0]);

    for (i = 0; i < argc - 1; i++) {
        char *ifname = argv[i+1];

        if (!strcmp(ifname, "--unload")) {
            unload = true;
            continue;
        }
        
       if (ifindex)
          return usage(argv[0]);

       ifindex = if_nametoindex(ifname);
       if (!ifindex) {
           fprintf(stderr, "Couldn't find interface '%s'\n", ifname);
           return 1;
       }
    }

    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/clean-dns-%d", ifindex);
    pin_path[sizeof(pin_path) - 1] = '\0';

    if (unload)
        goto unload;

    skel = clean_dns_kern__open();
    err = libbpf_get_error(skel);
    if (err) {
        fprintf(stderr, "Couldn't open BPF skeleton: %s\n", strerror(errno));
        return err;
    }

    err = clean_dns_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load object\n");
        goto out;
    }

    egress_fd = bpf_program__fd(skel->progs.tc_egress);
    if (egress_fd < 0) {
        fprintf(stderr, "Couldn't find program 'tc_egress'\n");
        err = -ENOENT;
        goto out;
    }
    
    ingress_fd = bpf_program__fd(skel->progs.tc_ingress);
    if (ingress_fd < 0) {
        fprintf(stderr, "Couldn't find program 'filter_ingress_pkt'\n");
        err = -ENOENT;
        goto out;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_egress,
                .prog_fd = egress_fd);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress,
                .prog_fd = ingress_fd);

    char ifname[IF_NAMESIZE];

    if (!if_indextoname(ifindex, ifname)) {
        err = -errno;
        fprintf(stderr, "Couldn't get ifname for ifindex %d: %s\n", ifindex, strerror(-err));
        goto out;
    }

    hook.ifindex = ifindex;
    hook.attach_point =  BPF_TC_EGRESS | BPF_TC_INGRESS;
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Couldn't create egress hook for interface %s\n", ifname);
        goto unload;
    }

    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &attach_egress);
    if (err) {
        fprintf(stderr, "Couldn't attach egress program to interface %s: %s\n", ifname, strerror(errno));
        goto unload;
    }

    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &attach_ingress);
    if (err) {
        fprintf(stderr, "Couldn't attach ingress program to interface %s: %s\n", ifname, strerror(errno));
        goto unload;
    }

out:
    clean_dns_kern__destroy(skel);
    return err;

unload:
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS;
    _err = bpf_tc_hook_destroy(&hook);
    if (_err) {
       fprintf(stderr, "Couldn't remove clsact qdisc on %s\n", ifname);
       err = _err;
    }
    unlink(pin_path);
    goto out;
}
