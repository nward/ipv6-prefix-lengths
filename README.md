# IPv6 Prefix Lengths
Given a pcap file, extract all IPv6 addresses and estimate the prefix length assigned by the ISP.

## Method

Look for blocks of zeros in addresses between bits 48 and 63 (inclusive).

- If we see bits 48 through 63 all being zero, we assume a /48 prefix
- If any bits between 48 and 55 are one, and bits 56 through 63 are all zero, we assume a /56 prefix
- If any bits between 48 and 59 are one, and bits 60 through 63 all being zero, we assume a /60 prefix
- If we see any bits between 48 and 64, we assume a /64 prefix

For prefix lengths 48, 56, and 60, if bit 64 is 1, we assume the address is from a second subnet within the ISP assigned prefix.

## Issues

This is not 100% accurate, but is "good enough" for getting a rough steer.

## Further work

Getting averages by RIR assignments and economies would be interesting. In particular the RIR assignment average my improve confidence in the estimates.

## Sample output

```
Total unique addresses: 936

Number of prefixes by length
48: 10
56: 196
60: 210
64: 520

Subnet 1 within a prefix by length:
48: 2
56: 20
60: 43
```
