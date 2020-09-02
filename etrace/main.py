#!/usr/bin/env python

import argparse
import json
import os
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw, conf, sr, send
from scapy.arch import linux as scapy_linux
from scapy.arch.bpf import core as scapy_core


class eTrace:
    def __init__(self, destination, nb_path, nb_per_path, pretty):
        self.destination = destination
        self.nb_path = nb_path
        self.nb_per_path = nb_per_path
        self.pretty = pretty
        self.packets = []
        self.links = defaultdict(lambda: defaultdict(int))
        self.result = None

    def fill_blanks(self, trace):
        for i in range(1, 31):
            if not trace.get(i):
                trace[i] = {}
                trace[i]["hop_ip"] = "..."
                trace[i]["latency"] = 0
                trace[i]["loss"] = 0

    def show_traceroute(self):
        print("traceroute to {}".format(self.destination))
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
        # get info of all paths
        results = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        for identifier, path in self.result.items():
            for hop, info in path.items():
                if not "hop_ip" in info:
                    continue

                previous_hop = "self" if hop == 1 else path[hop - 1]["hop_ip"]
                hop_ip = info["hop_ip"]
                nb_packets = info["sent"] - info["loss"]

                results[hop][previous_hop][hop_ip] += nb_packets

                if hop_ip == self.destination:
                    break

        # reorder by hop instead of paths
        for hop, hop_data in results.items():
            for a_end, a_end_info in hop_data.items():
                for z_end, z_end_count in a_end_info.items():
                    self.links[a_end][z_end] += z_end_count

        if self.pretty:
            return json.dumps(self.links, indent=2)

        return {k: dict(v) for k, v in self.links.items()}

    @staticmethod
    def _rematch(ans, unans):
        packets = {}
        # we record "unanswered" packets
        for pkt in unans:
            seq = pkt[0].seq
            if seq not in packets:
                packets[seq] = {}

            packets[seq][0] = pkt[0]

        # we record sent packets
        for pkt in ans:
            # sequence of sent packet
            seq = pkt[0].seq

            # we store packets
            if seq not in packets:
                packets[seq] = {}
            packets[seq][0] = pkt[0]

        # we record received packets
        for pkt in ans:
            recv = pkt[1]
            if recv.payload.name == "ICMP":
                seq_id = recv[0]["TCPerror"].seq
            elif recv.payload.name == "TCP":
                seq_id = recv[0][TCP].ack - 1
            else:
                raise RuntimeError("Sent packet not found")
            packets[seq_id][1] = pkt[1]

        # we resort the dict by key (which is the unique identifer of the packet)
        return {k: v for k, v in sorted(packets.items())}


    def tcpsyn_trace(self):
        """TCP syn traceroute."""
        # Non promiscuous mode
        conf.promisc = 0
        conf.sniff_promisc = 0
        reset_packets = []

        seq_id = 1
        for src_port in range(65000, 65000 + self.nb_path):
            for ttl in range(1, 31):
                for i in range(0, self.nb_per_path):
                    pkt = (
                        IP(dst=self.destination, ttl=ttl)
                        / TCP(flags="S", seq=seq_id, sport=src_port, dport=443)
                    )
                    self.packets.append(pkt)
                    seq_id += 1

                    reset = (
                        IP(dst=self.destination, ttl=ttl)
                        / TCP(flags="R", seq=seq_id, sport=src_port, dport=443)
                    )
                    reset_packets.append(reset)

        ans, unans = sr(
            self.packets,
            timeout=1,
            inter=0,
            verbose=0,
            filter=f"(tcp and dst portrange 65000-{65000 + self.nb_path}) or icmp",
        )

        # close TCP requests
        send(reset_packets, inter=0, verbose=0)

        packets = self._rematch(ans, unans)

        self.result = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        # results analysis
        for pkt in packets.values():
            sent_pkt = pkt[0]

            # answered packet
            if pkt.get(1):
                recv_pkt = pkt[1]
                hop_ip = recv_pkt[IP].src
                sport = sent_pkt[TCP].sport
                ttl = sent_pkt[IP].ttl

                self.result[sport][ttl]["hop_ip"] = hop_ip
                self.result[sport][ttl]["latency"] = recv_pkt.time - sent_pkt.sent_time
                self.result[sport][ttl]["sent"] += 1

            # unanswered
            else:
                sport = sent_pkt[TCP].sport
                ttl = sent_pkt[IP].ttl
                if not "hop_ip" in self.result[sport][ttl]:
                    self.result[sport][ttl]["hop_ip"] = "..."
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
        "--pretty",
        action="store_true",
        help="pretty output",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show all paths",
    )

    args = parser.parse_args()

    trace = eTrace(args.destination, args.paths, args.nb, args.pretty)
    trace.tcpsyn_trace()

    print(trace.find_links())

    if args.verbose:
        trace.show_traceroute()
