import pcap
import dpkt
import argparse

def capt_data(network, port, filename):
	pc = pcap.pcap(network)
	pc.setfilter('tcp port ' + port)
	for ptime, pdata in pc:
		p = dpkt.ethernet.Ethernet(pdata)
		if (p.data.__class__.__name__ == 'IP'):
			if (p.data.data.data != "" and p.data.data.data != "\n"):
				src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
				dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
				d = src.ip + ' -> ' + dst.ip + ' ' + p.data.data.data
				with open(filename, 'a') as f:
					f.writeline(d)
					f.writeline(ip, p.data.data.data.encode("hex"))


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("network", help = " The network you want to record the traffic")
	parser.add_argument("port", help = " The port you want to record the traffic")
	parser.add_argument("filename", help = " The filename you want to write the log")
	args = parser.parse_args()
	capt_data(args.network, args.port, args.filename)