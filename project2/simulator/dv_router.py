"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = False
    POISON_REVERSE = False
    # -----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = False

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####

        ##### End Stage 10A #####

    # ====== Helper Methods ======
    
    def _is_valid_input(self, *values):
        """Check if all values are non-None."""
        return all(v is not None for v in values)
    
    def _is_reachable(self, latency):
        """Check if a route is reachable (latency < INFINITY)."""
        return latency is not None and latency < INFINITY
    
    def _is_valid_latency(self, latency):
        """Check if latency is valid (non-None and non-negative)."""
        return latency is not None and latency >= 0
    
    def _cap_at_infinity(self, latency):
        """Ensure latency doesn't exceed INFINITY."""
        return INFINITY if latency > INFINITY else latency
    
    def _get_advertised_latency(self, entry, port):
        """Determine the latency to advertise for this route/port pair."""
        latency = entry.latency
        
        # Don't advertise routes back on the incoming port (split horizon)
        if self.SPLIT_HORIZON and entry.port == port:
            return None
        
        # Advertise infinite cost back on incoming port (poison reverse)
        if self.POISON_REVERSE and entry.port == port:
            return INFINITY
        
        # Handle invalid latencies
        if not self._is_valid_latency(latency):
            return INFINITY
        
        # Prevent counting to infinity by capping at INFINITY
        return self._cap_at_infinity(latency)

    # ====== Route Management ======

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        if not self._is_valid_input(host, port):
            return
        
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####
        latency = self.ports.get_latency(port)
        if not self._is_valid_latency(latency):
            return
        
        entry = TableEntry(
            dst=host,
            port=port,
            latency=latency,
            expire_time=FOREVER
        )
        self.table[host] = entry
        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        
        ##### Begin Stage 2 #####
        if not self._is_valid_input(packet, packet.dst if packet else None):
            return
        
        route = self.table.get(packet.dst)
        if route and self._is_reachable(route.latency):
            self.send(packet, port=route.port)
        ##### End Stage 2 #####

    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####
        ports = self.ports.get_all_ports()
        if not ports:
            return
        
        for port in ports:
            if not port:
                continue
            
            for entry in self.table.values():
                if not self._is_valid_input(entry, entry.dst if entry else None):
                    continue
                
                advertised_latency = self._get_advertised_latency(entry, port)
                if advertised_latency is None:
                    continue
                
                self.send_route(port, entry.dst, advertised_latency)
        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Removes expired routes from the table, optionally poisoning them first.
        
        Poisoned routes (INFINITY latency) are advertised periodically to 
        help neighbors converge faster.
        """
        
        ##### Begin Stages 5, 9 #####
        for destination in list(self.table):
            if not destination:
                continue
            
            entry = self.table.get(destination)
            if not entry or not entry.has_expired:
                continue
            
            if self.POISON_EXPIRED and entry.port:
                self.table[destination] = TableEntry(
                    dst=destination,
                    port=entry.port,
                    latency=INFINITY,
                    expire_time=api.current_time() + self.ROUTE_TTL
                )
            else:

                self.table.pop(destination)
        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.
        
        Updates the routing table based on the advertised route, using the
        Bellman-Ford equation to find the shortest path.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        link_latency = self.ports.get_latency(port)
        if not self._is_valid_latency(link_latency):
            return
        
        total_latency = route_latency + link_latency
        total_latency = self._cap_at_infinity(total_latency)
        
        current_entry = self.table.get(route_dst)
        
        should_update = (
            current_entry is None or                   # Rule 1: no route yet
            current_entry.port == port or              # Rule 2: from current next-hop
            total_latency < current_entry.latency      # Rule 3: strictly better
        )
        
        if should_update:
            self.table[route_dst] = TableEntry(
                dst=route_dst,
                port=port,
                latency=total_latency,
                expire_time=api.current_time() + self.ROUTE_TTL
            )
        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        if not self._is_valid_input(port) or not self._is_valid_latency(latency):
            return
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####

        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        if not port:
            return
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####

        ##### End Stage 10B #####

    # Feel free to add any helper methods!
