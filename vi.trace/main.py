#!/usr/bin/env python

from scapy.all import IP, TCP, UDP, sr, Raw
import time


class ViTrace:
    def __init__(self):
        self.packets = []
        return

    def fill_blanks(self, trace):
        for i in range(1, 31):
            if not trace.get(i):
                trace[i] = {}
                trace[i]["hop_ip"] = "..."
                trace[i]["latency"] = 0
                trace[i]["loss"] = 0

    def show_traceroute(self, result, destination):
        print("traceroute to {}".format(destination))
        for ident, trace in result.items():
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
                if trace[hop] == destination:
                    break
        return

    def tcpsyn_trace(self, destination="13.210.72.83", parallel=4, loop=1):
        """TCP syn traceroute."""

        start = time.time()

        for src_port in range(65000, 65000 + parallel):
            for ttl in range(1, 31):
                for i in range(0, loop):
                    pkt = (
                        IP(dst=destination, ttl=ttl)
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

        sent = time.time()

        result = {}

        # need to integrate seq id to ensure matching sent with receive
        for i in ans:
            hop_ip = i[1][IP].src
            sport = i[0][TCP].sport
            ttl = i[0][IP].ttl
            if not result.get(sport):
                result[sport] = {}
            if not result[sport].get(ttl):
                result[sport][ttl] = {}
                result[sport][ttl]["loss"] = 0
                result[sport][ttl]["sent"] = 0
            result[sport][ttl]["hop_ip"] = hop_ip
            result[sport][ttl]["latency"] = i[1].time - i[0].sent_time
            result[sport][ttl]["sent"] += 1

        for i in unans:
            sport = i[0][TCP].sport
            ttl = i[0][IP].ttl
            if not result.get(sport):
                result[sport] = {}
            if not result[sport].get(ttl):
                result[sport][ttl] = {}
                result[sport][ttl]["loss"] = 0
                result[sport][ttl]["sent"] = 0
            result[sport][ttl]["loss"] += 1
            result[sport][ttl]["sent"] += 1

        self.show_traceroute(result, destination)

        print("")
        print("preparation: {}".format(prepared - start))
        print("sent: {}".format(sent - prepared))

        return

    def main(self):
        self.tcpsyn_trace(loop=10)
        return


if __name__ == "__main__":
    trace = ViTrace()
    trace.main()
