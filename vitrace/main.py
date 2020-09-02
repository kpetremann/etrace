#!/usr/bin/env python

import argparse
import json
import os
import time
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw, conf, sr
from scapy.arch import linux as scapy_linux
from scapy.arch.bpf import core as scapy_core


class ViTrace:
    def __init__(self, destination, nb_path, nb_per_path, pretty):
        self.destination = destination
        self.nb_path = nb_path
        self.nb_per_path = nb_per_path
        self.pretty = pretty
        self.packets = []
        self.result = {}
        self.links = defaultdict(lambda: defaultdict(int))

    def fill_blanks(self, trace):
        for i in range(1, 31):
            if not trace.get(i):
                trace[i] = {}
                trace[i]["hop_ip"] = "..."
                trace[i]["latency"] = 0
                trace[i]["loss"] = 0

    def show_traceroute(self):
        print("traceroute to {}".format())
        for ident, trace in self.result.items():
            self.fill_blanks(trace)
            print("")
            for hop in trace:
                loss_ratio = trace[hop].get("loss", 0) / trace[hop].get("sent", 0)
                print(
                    "path #{}/{}: {} (latency: {}ms, loss: {}%, sent: {}, lost: {})".format(
                        ident,
                        hop,
                        trace[hop].get("hop_ip"),
                        round(trace[hop].get("latency", 0) * 1000, 2),
                        loss_ratio * 100,
                        trace[hop].get("loss", 0),
                        trace[hop].get("loss", 0),
                    )
                )
                if trace[hop].get("hop_ip") == self.destination:
                    break

    def find_links(self):
        for identifier, path in self.result.items():
            previous_hop = "self"
            for hop, info in path.items():
                if not "hop_ip" in info:
                    continue
                hop_ip = info["hop_ip"]
                nb_packets = info["sent"] - info["loss"]
                self.links[previous_hop][hop_ip] += nb_packets
                previous_hop = hop_ip

        if self.pretty:
            return json.dumps(self.links, indent=2)

        return {k: dict(v) for k, v in self.links.items()}


    def tcpsyn_trace(self):
        """TCP syn traceroute."""
        # Non promiscuous mode
        conf.promisc = 0
        conf.sniff_promisc = 0

        start = time.time()

        for src_port in range(65000, 65000 + self.nb_path):
            for ttl in range(1, 31):
                for i in range(0, self.nb_per_path):
                    pkt = (
                        IP(dst=self.destination, ttl=ttl)
                        / TCP(flags="S", seq=ttl, sport=src_port, dport=80)
                        / Raw(str(src_port) + "/" + str(ttl))
                    )
                    self.packets.append(pkt)

        prepared = time.time()

        ans, unans = sr(
            self.packets,
            timeout=1,
            inter=0,
            verbose=0,
            filter="(tcp and dst portrange 65000-65100) or icmp",
        )

        self.result = {}

        # need to integrate seq id to ensure matching sent with receive
        for i in ans:
            hop_ip = i[1][IP].src
            sport = i[0][TCP].sport
            ttl = i[0][IP].ttl
            if not self.result.get(sport):
                self.result[sport] = {}
            if not self.result[sport].get(ttl):
                self.result[sport][ttl] = {}
                self.result[sport][ttl]["loss"] = 0
                self.result[sport][ttl]["sent"] = 0
            self.result[sport][ttl]["hop_ip"] = hop_ip
            self.result[sport][ttl]["latency"] = i[1].time - i[0].sent_time
            self.result[sport][ttl]["sent"] += 1

        for i in unans:
            sport = i[0][TCP].sport
            ttl = i[0][IP].ttl
            if not self.result.get(sport):
                self.result[sport] = {}
            if not self.result[sport].get(ttl):
                self.result[sport][ttl] = {}
                self.result[sport][ttl]["loss"] = 0
                self.result[sport][ttl]["sent"] = 0
            self.result[sport][ttl]["loss"] += 1
            self.result[sport][ttl]["sent"] += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--destination",
        action="store",
        type=str,
        required=True,
        help="destination",
    )
    parser.add_argument(
        "-n",
        "--nb",
        action="store",
        type=int,
        default=1,
        help="number of packets sent per path",
    )
    parser.add_argument(
        "-p",
        "--paths",
        action="store",
        type=int,
        default=1,
        help="number of paths to test",
    )
    parser.add_argument(
        "--pretty", action="store_true", help="pretty output",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="show all paths",
    )

    args = parser.parse_args()

    trace = ViTrace(args.destination, args.paths, args.nb, args.pretty)
    trace.tcpsyn_trace()

    print(trace.find_links())

    if args.verbose:
        trace.show_traceroute()
