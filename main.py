import ipaddress
import bitstring
import logging
import argparse

parser = argparse.ArgumentParser(
    prog="ipv6-prefix-lengths",
)
parser.add_argument('-v', '--verbose', action='count', default=0)
input_file = parser.add_mutually_exclusive_group(required=True)
input_file.add_argument('-p', '--pcap-file')
input_file.add_argument('-t', '--text-file')
args = parser.parse_args()

if args.verbose >= 2:
    logging.basicConfig(level = logging.DEBUG)
elif args.verbose >= 1:
    logging.basicConfig(level = logging.INFO)
else:
    logging.basicConfig(level = logging.WARNING)

addresses: set[str] = set()
slash_64s: set[str] = set()

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

count = 0

if args.text_file:
    file = open(args.text_file)

    for address in file.readlines():
        address_obj = ipaddress.ip_address(address.strip())
        addresses.add(address_obj)

        prefix = ipaddress.ip_network((address_obj,64),strict=False)
        slash_64s.add(prefix)

        count += 1
        if count % 100000 == 0:
            logging.info("import: %d" % count)


if args.pcap_file:
    from scapy.all import PcapReader
    packets = PcapReader(args.pcap_file)

    for packet in packets:
        if not "IPv6" in packet:
            continue

        # Source address
        address_obj = ipaddress.ip_address(packet["IPv6"].src)
        addresses.add(address_obj)

        prefix = ipaddress.ip_network((address_obj,64),strict=False)
        slash_64s.add(prefix)

        # Destination address
        address_obj = ipaddress.ip_address(packet["IPv6"].dst)
        addresses.add(address_obj)

        prefix = ipaddress.ip_network((address_obj,64),strict=False)
        slash_64s.add(prefix)

        count += 1
        if count % 100000 == 0:
            logging.info("import: %d" % count)

logging.info("Import complete, %d addresses, %d from /64s" % (len(addresses), len(slash_64s)))

count = 0

for address in addresses:
    address_bitarray = bitstring.BitArray(address.packed)
    logging.debug("%s: %s" % (address_bitarray.bin, address))
    logging.debug("prefix bits: %s" % address_bitarray[48:63])
    length = None

    if address_bitarray[48:63].int == 0:
        length = 48
    elif address_bitarray[56:63].int == 0:
        length = 56
    elif address_bitarray[60:63].int == 0:
        length = 60
    elif address_bitarray[48:64].int != 0:
        length = 64
    else:
        logging.warning("Unknown: %s" % address)

    if length:
        prefix_lengths[length] += 1
        if length <= 63:
            if address_bitarray[63]:
                prefix_length_extranets[length] += 1
                logging.debug("length assumed to be %d with subnet 1" % length)
            else:
                logging.debug("length assumed to be %d without subnet 1" % length)
        else:
            logging.debug("length assumed to be %d" % length)

    count += 1
    if count % 100000 == 0:
        logging.info("Processing addresses: %d" % count)

logging.info("Processing complete")

print("Total unique addresses: %d" % len(addresses))
print()
print("Number of addresses by prefix length")
for prefix_length in prefix_lengths.keys():
    print("%d: %d (%0.2f%%)" % (prefix_length, prefix_lengths[prefix_length], prefix_lengths[prefix_length]/len(addresses) * 100))
print()
print("Number of addresses with subnet 1 within a prefix by length:")
for prefix_length in prefix_length_extranets.keys():
    print("%d: %d (%0.2f%%)" % (prefix_length, prefix_length_extranets[prefix_length], (prefix_length_extranets[prefix_length] / prefix_lengths[prefix_length] * 100 if prefix_lengths[prefix_length] else 0)))
