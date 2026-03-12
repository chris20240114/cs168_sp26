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
        self.history = {}  # {port: {destination: latency}}
        ##### End Stage 10A #####

    # ====== Some useful Helper Methods ======
    
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
    
    def _has_route_changed(self, port, destination, current_latency):
        """Check if a route has changed since last advertisement.
        
        Returns True if this route is new or latency differs from what was previously advertised.
        """
        if port not in self.history:
            return True
        if destination not in self.history[port]:
            return True
        return self.history[port][destination] != current_latency
    
    def _update_history(self, port, destination, latency):
        """Record the route we just advertised in our history."""
        if port not in self.history:
            self.history[port] = {}
        self.history[port][destination] = latency

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
        
        route_entry = TableEntry(
            dst=host,
            port=port,
            latency=latency,
            expire_time=FOREVER
        )
        self.table[host] = route_entry
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
        packet_is_valid = self._is_valid_input(packet, packet.dst if packet else None)
        if not packet_is_valid:
            return
        
        route_to_destination = self.table.get(packet.dst)
        route_exists = route_to_destination is not None
        route_is_reachable = route_exists and self._is_reachable(route_to_destination.latency)
        
        if route_is_reachable:
            self.send(packet, port=route_to_destination.port)
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
        all_ports = self.ports.get_all_ports()
        if not all_ports:
            return
        
        ports_to_advertise = [single_port] if single_port is not None else all_ports
        
        for outgoing_port in ports_to_advertise:
            if not outgoing_port:
                continue
            
            for route_entry in self.table.values():
                entry_is_valid = self._is_valid_input(route_entry, route_entry.dst if route_entry else None)
                if not entry_is_valid:
                    continue
                
                cost_to_advertise = self._get_advertised_latency(route_entry, outgoing_port)
                should_suppress = cost_to_advertise is None
                if should_suppress:
                    continue
                
                is_changed = self._has_route_changed(outgoing_port, route_entry.dst, cost_to_advertise)
                should_send = force or is_changed
                
                if should_send:
                    self.send_route(outgoing_port, route_entry.dst, cost_to_advertise)
                    self._update_history(outgoing_port, route_entry.dst, cost_to_advertise)
        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Removes expired routes from the table, optionally poisoning them first.
        
        Poisoned routes (INFINITY latency) are advertised periodically to 
        help neighbors converge faster.
        """
        
        ##### Begin Stages 5, 9 #####
        for dest in list(self.table):
            if not dest:
                continue
            
            route_entry = self.table.get(dest)
            if not route_entry or not route_entry.has_expired:
                continue
            
            should_poison = self.POISON_EXPIRED and route_entry.port
            if should_poison:
                poisoned_entry = TableEntry(
                    dst=dest,
                    port=route_entry.port,
                    latency=INFINITY,
                    expire_time=api.current_time() + self.ROUTE_TTL
                )
                self.table[dest] = poisoned_entry
            else:
                self.table.pop(dest)
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
        link_cost = self.ports.get_latency(port)
        if not self._is_valid_latency(link_cost):
            return
        
        cost_via_neighbor = route_latency + link_cost
        cost_via_neighbor = self._cap_at_infinity(cost_via_neighbor)
        
        existing_route = self.table.get(route_dst)
        
        no_route_exists = existing_route is None
        from_current_neighbor = existing_route and existing_route.port == port
        is_shorter_path = existing_route and cost_via_neighbor < existing_route.latency
        
        should_update = no_route_exists or from_current_neighbor or is_shorter_path
        
        if should_update:
            self.table[route_dst] = TableEntry(
                dst=route_dst,
                port=port,
                latency=cost_via_neighbor,
                expire_time=api.current_time() + self.ROUTE_TTL
            )
            self.send_routes(force=False)
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
        should_announce_to_new_neighbor = self.SEND_ON_LINK_UP
        if should_announce_to_new_neighbor:
            self.send_routes(force=True, single_port=port)
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
        affected_routes = []
        for dest, route_entry in list(self.table.items()):
            uses_failed_port = route_entry.port == port
            if uses_failed_port:
                affected_routes.append(dest)
        
        should_poison_routes = self.POISON_ON_LINK_DOWN
        if should_poison_routes:
            for dest in affected_routes:
                old_entry = self.table[dest]
                self.table[dest] = TableEntry(
                    dst=dest,
                    port=old_entry.port,
                    latency=INFINITY,
                    expire_time=api.current_time() + self.ROUTE_TTL
                )
            self.send_routes(force=False)
        else:
            for dest in affected_routes:
                self.table.pop(dest)
        ##### End Stage 10B #####

    # Feel free to add any helper methods!
