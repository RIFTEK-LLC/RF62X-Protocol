# RF62X-Protocol for scanners series RF62X

```txt
#############################################################################################
Help information for TestSender:
-----------------
 --host_device_uid         Source device ID ("2" by default)
 --host_ip_addr            Host IP-addr ("127.0.0.1" by default)
 --dst_ip_addr             Destination IP-addr ("127.0.0.1" by default)
 --host_udp_port           Host UDP Port ("0" by default)
 --dst_udp_port            Destination UDP Port ("50020" by default)
 --socket_timeout          Socket waiting time for data [ms] ("100" ms by default)
 --max_packet_size         Maximum UDP packet size [bytes] ("1024" bytes by default)
 --max_data_size           Maximum protocol packet size [bytes] ("1048576" bytes by default)

An example command line would look like this:
---------------------------------------------
 TestSender --dst_ip_addr 127.0.0.1 --dst_udp_port 50020
#############################################################################################


#############################################################################################
Help information for TestReceiver:
-----------------
 --host_device_uid         Host device ID ("1" by default)
 --host_ip_addr            Host IP-addr ("127.0.0.1" by default)
 --dst_ip_addr             Destination IP-addr ("127.0.0.1" by default)
 --host_udp_port           Host UDP Port ("50020" by default)
 --dst_udp_port            Destination UDP Port ("0" by default)
 --socket_timeout          Socket waiting time for data [ms] ("100" ms by default)
 --max_packet_size         Maximum UDP packet size [bytes] ("1024" bytes by default)
 --max_data_size           Maximum protocol packet size [bytes] ("1048576" bytes by default)

An example command line would look like this:
---------------------------------------------
 TestReceiver --host_ip_addr 127.0.0.1 --host_udp_port 50020
#############################################################################################
```
