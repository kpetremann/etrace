#!/usr/bin/env python

from scapy.all import IP, TCP, UDP, sr, Raw


class ViTrace:
    def __init__(self):
        self.packets = []
        return

    def fill_blanks(self, trace):
        for i in range(1,31):
            if not trace.get(i):
                trace[i] = "..."

    def show_traceroute(self, result, destination):
        print("traceroute to {}".format(destination))
        for ident, trace in result.items():
            self.fill_blanks(trace)
            print("")
            for hop in trace:
                print("path #{}/{}: {}".format(ident, hop, trace[hop]))
                if trace[hop] == destination:
                    break

        return

    def tcpsyn_trace(self, destination="13.210.72.83", parallel=4):
        """TCP syn traceroute."""

        for src_port in range(65000, 65000 + parallel):
            for ttl in range(1, 31):
                pkt = (
                    IP(dst=destination, ttl=ttl)
                    / TCP(flags="S", seq=ttl, sport=src_port, dport=80)
                    / Raw(str(src_port) + "/" + str(ttl))
                )
                self.packets.append(pkt)

        ans, unans = sr(
            self.packets,
            timeout=1,
            inter=0,
            verbose=0,
            filter="(tcp and dst portrange 65000-65100) or icmp",
        )
        
        result = {}

        for i in ans:
            hop_ip = i[1][IP].src
            sport = i[0][TCP].sport
            ttl = i[0][IP].ttl
            if not result.get(sport):
                result[sport] = {}
            result[sport][ttl] = hop_ip

        self.show_traceroute(result, destination)
        return

    def main(self):
        self.tcpsyn_trace()
        return


if __name__ == "__main__":
    trace = ViTrace()
    trace.main()
