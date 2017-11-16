# python-traffic-recorder
A simple traffic recorder for CTF Pwn problems
## Requirements
```shell
apt install python-libpcap
apt install libpcap-dev
apt install python-dpkt
apt install python-daemon
pip install pypcap
```
## Usage
```shell
[sudo] python recorder.py network port filename
Example:
sudo python recorder.py eth0 23333 /var/log/pwn.log
```