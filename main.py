from scapy.all import rdpcap, PacketList, Packet
import ipaddress
import bitstring
import logging

logging.basicConfig(level= logging.INFO)

packets: PacketList = rdpcap("sample.pcap")

addresses: set[str] = set()

prefix_lengths = {
    48: 0,
    56: 0,
    60: 0,
    64: 0,
}

prefix_length_extranets = {
    48: 0,
    56: 0,
    60: 0,
}

for packet in packets:
    if not "IPv6" in packet:
        continue

    address = None
    if packet["IPv6"].src != "2402:f300:8000::4":
        address = packet["IPv6"].src
    elif packet["IPv6"].dst != "2402:f300:8000::4":
        address = packet["IPv6"].dst

    address_obj = ipaddress.ip_address(address)
    addresses.add(address_obj)

for address in addresses:
    logging.debug(bitstring.BitArray(address.packed)[48:63])
    if bitstring.BitArray(address.packed)[48:63].int == 0:
        logging.debug("48")
        prefix_lengths[48] += 1
        if bitstring.BitArray(address.packed)[63]:
            prefix_length_extranets[48] += 1
    elif bitstring.BitArray(address.packed)[48:56].int != 0 and bitstring.BitArray(address.packed)[56:63].int == 0:
        logging.debug("56")
        prefix_lengths[56] += 1
        if bitstring.BitArray(address.packed)[63]:
            prefix_length_extranets[56] += 1
    elif bitstring.BitArray(address.packed)[48:60].int != 0 and bitstring.BitArray(address.packed)[60:63].int == 0:
        logging.debug("60")
        prefix_lengths[60] += 1
        if bitstring.BitArray(address.packed)[63]:
            prefix_length_extranets[60] += 1
    elif bitstring.BitArray(address.packed)[48:64].int != 0:
        logging.debug("64")
        prefix_lengths[64] += 1

print("Total unique addresses: %d" % len(addresses))
print()
print("Number of prefixes by length")
for prefix_length in prefix_lengths.keys():
    print("%d: %d" % (prefix_length, prefix_lengths[prefix_length]))
print()
print("Subnet 1 within a prefix by length:")
for prefix_length in prefix_length_extranets.keys():
    print("%d: %d" % (prefix_length, prefix_length_extranets[prefix_length]))
