#!/usr/bin/python
import pcap
import dpkt
import argparse
import daemon
import time

def capt_data(network, port, filename):
	pc = pcap.pcap(network)
	pc.setfilter('tcp port ' + port)
	for ptime, pdata in pc:
		p = dpkt.ethernet.Ethernet(pdata)
		if (p.data.__class__.__name__ == 'IP'):
			if (p.data.data.data != "" and p.data.data.data != "\n"):
				src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
				dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
				t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ptime))
				d = t + ' ' + src_ip + ' -> ' + dst_ip + ' ' + p.data.data.data + '\n'
				with open(filename, 'a') as f:
					f.write(d)
					f.write(p.data.data.data.encode("hex") + '\n')


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("network", help = " The network you want to record the traffic")
	parser.add_argument("port", help = " The port you want to record the traffic")
	parser.add_argument("filename", help = " The filename you want to write the log")
	args = parser.parse_args()
	with daemon.DaemonContext():
		capt_data(args.network, args.port, args.filename)