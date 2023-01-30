# Zeek ICMP Exfil Detection
This script identifies data exfiltration over the ICMP protocol. It measures odd activities like unmatching echo reply payloads and differing payload contents between echo reply pairs. 

## Background
This is the result of my interest to learn Zeek scripting and also to detect exfiltration of data over a protocol which is unexpected to be used for such. 
This script will detect exfil/tunneling from the following tools:

- [Data Exfiltration Toolkit](https://github.com/sensepost/DET)
- [Icmp File Transfer](https://github.com/Vidimensional/Icmp-File-Transfer)
- [Hping3](https://www.phoenixinfosec.com/post/data-exfiltration-with-hping3)
- [PyExfil](https://github.com/ytisf/PyExfil)
- [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)

## Install
```zkg install https://github.com/Sithari/icmp-exfil-detection```

## How It Works

This script will create a notice.log entry when it identifies one of the following patterns in ICMP traffic:

ICMP_DataExfil, data transfer over icmp exceeding set threshold

ICMP_UnpairedEchoReply, echo reply seen without echo request

ICMP_AsymPayload, payload in icmp req != icmp resp 

ICMP_AsymPayloadFlow, echo + reply in current connection is different than previous


Here is an example output based on the [EgressAssess-sample-2mb-text-file.pcap](https://github.com/Sithari/icmp-exfil-detection/blob/main/pcaps/EgressAssess-sample-2mb-text-file.pcap) created by Rakesh Passa.

```
{
  "ts": 1665586502.175499,
  "note": "ICMP::ICMP_DataExfil",
  "msg": "Exfil of size 3.00 MB bytes seen between 192.168.86.36 and 54.144.215.114. Start time: 10:54:26 12/10/2022 EDT-0400. End time: 10:54:58 12/10/2022 EDT-0400. Total duration: 31.0 secs 602.0 msecs 305.173874 usecs",
  "sub": "Source: 192.168.86.36, Destination: 54.144.215.114, Start time: 1665586466.542945, End time: 1665586498.14525, Duration: 31.0 secs 602.0 msecs 305.173874 usecs, Bytes sent: 2998380, Bytes recieved: 2998380, Event count: 2064",
  "src": "192.168.86.36",
  "dst": "54.144.215.114",
  "actions": [
    "Notice::ACTION_LOG"
  ],
  "email_dest": [],
  "suppress_for": 0
}
```

## References 
- [IETF's RFC 792 for ICMP](https://datatracker.ietf.org/doc/html/rfc792)
- [MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/)

## Disclaimer

There exists some tools which use ICMP in a custom matter, for example increment some value within the payload every echo reply. Situations like this can cause the exfil logic to trigger. 

## License

This project is licensed under the terms of the BSD 3-Clause License open source license. Please refer to LICENSE for the full terms.
