import util
import struct
# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        version_hl = buffer[0]
        self.version = version_hl >> 4
        self.header_len = (version_hl & 0x0F) * 4  # Length in bytes
        
        # Byte 1: Service type (also called DSCP and ECN bits)
        self.tos = buffer[1]
        
        # Bytes 2-3: length of the entire packet (header + payload)
        self.length = struct.unpack('!H', buffer[2:4])[0]
        
        # Bytes 4-5: ID
        self.id = struct.unpack('!H', buffer[4:6])[0]
        
        # Bytes 6-7: Flags and Fragment Offset
        flags_frag = struct.unpack('!H', buffer[6:8])[0]
        self.flags = flags_frag >> 13
        self.frag_offset = flags_frag & 0x1FFF
        
        # Byte 8: TTL
        self.ttl = buffer[8]
        
        # Byte 9: Protocol
        self.proto = buffer[9]
        
        # Bytes 10-11: Checksum
        self.cksum = struct.unpack('!H', buffer[10:12])[0]
        
        # Bytes 12-15: Source IP
        self.src = '.'.join(str(b) for b in buffer[12:16])
        
        # Bytes 16-19: Dest IP
        self.dst = '.'.join(str(b) for b in buffer[16:20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.type = buffer[0] # Byte 0: Type
        self.code = buffer[1] # Byte 1: Code
        self.cksum = struct.unpack('!H', buffer[2:4])[0] # Bytes 2-3: Checksum

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        self.src_port = struct.unpack('!H', buffer[0:2])[0] # Bytes 0-1: Source Port
        self.dst_port = struct.unpack('!H', buffer[2:4])[0] # Bytes 2-3: Destination Port
        self.len = struct.unpack('!H', buffer[4:6])[0] # Bytes 4-5: Length
        self.cksum = struct.unpack('!H', buffer[6:8])[0] # Bytes 6-7: Checksum

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    results = []
    payload = b"Potato."
    reached_destination = False
    
    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        routers_at_current_ttl = set()
        sendsock.set_ttl(ttl)

        for attempt_num in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto(payload, (ip, TRACEROUTE_PORT_NUMBER))
            if recvsock.recv_select():
                try:
                    response_packet, sender_address = recvsock.recvfrom()
                    responding_router_ip = IPv4(response_packet).src
                    routers_at_current_ttl.add(responding_router_ip)
                    if responding_router_ip == ip:
                        reached_destination = True
                        
                except Exception:
                    continue
        
        routers_discovered = list(routers_at_current_ttl)
        results.append(routers_discovered)
        
        util.print_result(routers_discovered, ttl)
        
        if reached_destination:
            break
    return results


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
