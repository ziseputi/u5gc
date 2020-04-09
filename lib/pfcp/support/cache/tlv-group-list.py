ies = []
ies.append({"ie_type": "Application ID", "ie_value": "Application ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the Application ID for which PFDs shall be provisioned in the UP function."})
ies.append({"ie_type": "PFD context", "ie_value": "PFD context", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the PFD needs to be provisioned in the UP function.When present, it shall describe the PFD to be provisioned in the UP function.Several IEs with the same IE type may be present to provision multiple PFDs for this Application ID.When this IE is absent, the UP function shall delete all the PFDs received and stored earlier in the UP function for this Application ID."})
group_list["Application ID's PFDs"] = {"index": "158", "type": "58", "ies": ies}
ies = []
ies.append({"ie_type": "PFD contents", "ie_value": "PFD Contents", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall describe the PFD to be provisioned in the UP function. Several IEs with the same IE type may be present to provision multiple contents for this PFD. (NOTE 1)"})
group_list["PFD context"] = {"index": "159", "type": "59", "ies": ies}
ies = []
ies.append({"ie_type": "Remote GTP-U Peer", "ie_value": "Remote GTP-U Peer ", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall include the IP address of the remote GTP-U peer towards which a user plane path failure has been detected.More than one IE with this type may be included to represent multiple remote GTP-U peers towards which a user plane path failure has been detected."})
group_list["User Plane Path Failure Report"] = {"index": "202", "type": "102", "ies": ies}
ies = []
ies.append({"ie_type": "PDR ID", "ie_value": "PDR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the PDR among all the PDRs configured for that PFCP session."})
ies.append({"ie_type": "Precedence", "ie_value": "Precedence", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the PDRs precedence to be applied by the UP function among all PDRs of the PFCP session, when looking for a PDR matching an incoming packet."})
ies.append({"ie_type": "PDI", "ie_value": "PDI", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the PDI against which incoming packets will be matched.See Table 7.5.2.2-2."})
ies.append({"ie_type": "Outer Header Removal", "ie_value": "Outer Header Removal", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to remove one or more outer header(s) from the packets matching this PDR."})
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Activate Predefined Rules IE is not included or if it is included but it does not result in activating a predefined FAR, and if the MAR ID is not included.When present this IE shall contain the FAR ID to be associated to the PDR."})
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a measurement action shall be applied to packets matching this PDR.When present, this IE shall contain the URR IDs to be associated to the PDR.Several IEs within the same IE type may be present to represent a list of URRs to be associated to the PDR."})
ies.append({"ie_type": "QER ID", "ie_value": "QER ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a QoS enforcement or QoS marking action shall be applied to packets matching this PDR.When present, this IE shall contain the QER IDs to be associated to the PDR. Several IEs within the same IE type may be present to represent a list of QERs to be associated to the PDR."})
ies.append(
    {"ie_type": "Activate Predefined Rules", "ie_value": "Activate Predefined Rules", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if Predefined Rule(s) shall be activated for this PDR. When present this IE shall contain one Predefined Rules name.Several IEs with the same IE type may be present to represent multiple Activate Predefined Rules names."})
ies.append({"ie_type": "Activation Time", "ie_value": "Activation Time", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the PDR activation shall be deferred. (NOTE 1)"})
ies.append({"ie_type": "Deactivation Time", "ie_value": "Deactivation Time", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the PDR deactivation shall be deferred. (NOTE 1)"})
ies.append({"ie_type": "MAR ID", "ie_value": "MAR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the PDR is provisioned to match the downlink traffic towards the UE for a PFCP session established for a MA PDU session."})
ies.append({"ie_type": "Packet Replication and Detection Carry-On Information",
            "ie_value": "Packet Replication and Detection Carry-On Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the PDR is provisioned to match a broadcast packet. When present, it contains the information to instruct the UPF to replicate the packet and to carry-on the look-up of other PDRs of other PFCP sessions matching the packet (see clause 5.2.1)."})
group_list["Create PDR"] = {"index": "101", "type": "1", "ies": ies}
ies = []
ies.append({"ie_type": "Source Interface", "ie_value": "Source Interface", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the source interface of the incoming packet."})
ies.append({"ie_type": "F-TEID", "ie_value": "Local F-TEID", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall not be present if Traffic Endpoint ID is present.If present, this IE shall identify the local F-TEID to match for an incoming packet.The CP function shall set the CHOOSE (CH) bit to 1 if the UP function supports the allocation of F-TEID and the CP function requests the UP function to assign a local F-TEID to the PDR."})
ies.append({"ie_type": "Network Instance", "ie_value": "Network Instance", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall not be present if Traffic Endpoint ID is present. It shall be present if the CP function requests the UP function to allocate a UE IP address/prefix and the Traffic Endpoint ID is not present.If present, this IE shall identify the Network instance to match for the incoming packet. See NOTE 1, NOTE2."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP address", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall not be present if Traffic Endpoint ID is present.If present, this IE shall identify the source or destination IP address to match for the incoming packet. (NOTE 5)The CP function shall set the CHOOSE (CH) bit to 1 if the UP function supports the allocation of UE IP address/ prefix and the CP function requests the UP function to assign a UE IP address/prefix to the PDR."})
ies.append({"ie_type": "Traffic Endpoint ID", "ie_value": "Traffic Endpoint ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE may be present if the UP function has indicated the support of PDI optimization.If present, this IE shall uniquely identify the Traffic Endpoint for that PFCP session.Several IEs with the same IE type may be present to provision several Traffic Endpoints with different Traffic Endpoint IDs, from which the UPF may receive packets pertaining to the same service data flow, which is subject for the same FAR, QER and URR, if the UPF has indicated it supports MTE feature as specified in clause 8.2.25. See NOTE 6."})
ies.append({"ie_type": "SDF Filter", "ie_value": "SDF Filter", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the SDF filter to match for the incoming packet. Several IEs with the same IE type may be present to provision a list of SDF Filters. The full set of applicable SDF filters, if any, shall be provided during the creation or the modification of the PDI.See NOTE 3."})
ies.append({"ie_type": "Application ID", "ie_value": "Application ID", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the Application ID to match for the incoming packet. "})
ies.append(
    {"ie_type": "Ethernet PDU Session Information", "ie_value": "Ethernet PDU Session Information", "presence": "O",
     "tlv_more": "0",
     "comment": "This IE may be present to identify all the (DL) Ethernet packets matching an Ethernet PDU session (see clause 5.13.1)."})
ies.append({"ie_type": "Ethernet Packet Filter", "ie_value": "Ethernet Packet Filter", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the Ethernet PDU to match for the incoming packet.Several IEs with the same IE type may be present to represent a list of Ethernet Packet Filters.The full set of applicable Ethernet Packet filters, if any, shall be provided during the creation or the modification of the PDI."})
ies.append({"ie_type": "QFI", "ie_value": "QFI", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall not be present if Traffic Endpoint ID is present and the QFI(s) are included in the Traffic Endpoint.If present, this IE shall identify the QoS Flow Identifier to match for the incoming packet.Several IEs with the same IE type may be present to provision a list of QFIs. When present, the full set of applicable QFIs shall be provided during the creation or the modification of the PDI. "})
ies.append({"ie_type": "Framed-Route", "ie_value": "Framed-Route", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe a framed route.Several IEs with the same IE type may be present to provision a list of framed routes. (NOTE 5)"})
ies.append({"ie_type": "Framed-Routing", "ie_value": "Framed-Routing", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe a framed route. "})
ies.append({"ie_type": "Framed-IPv6-Route", "ie_value": "Framed-IPv6-Route", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe a framed IPv6 route.Several IEs with the same IE type may be present to provision a list of framed IPv6 routes. (NOTE 5)"})
ies.append({"ie_type": "3GPP Interface Type", "ie_value": "Source Interface Type", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present to indicate the 3GPP interface type of the source interface, if required by functionalities in the UP Function, e.g. for performance measurements."})
group_list["PDI"] = {"index": "102", "type": "2", "ies": ies}
ies = []
ies.append({"ie_type": "Ethernet Filter ID", "ie_value": "Ethernet Filter ID", "presence": "C", "tlv_more": "0",
            "comment": "This shall be present if Bidirectional Ethernet filter is required. This IE shall uniquely identify an Ethernet Filter among all the Ethernet Filters provisioned for a given PFCP session."})
ies.append({"ie_type": "Ethernet Filter Properties", "ie_value": "Ethernet Filter Properties", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present when provisioning a bidirectional Ethernet Filter the first time (see clause 5.13.4)."})
ies.append({"ie_type": "MAC address", "ie_value": "MAC address", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the MAC address.This IE may be present up to 16 times."})
ies.append({"ie_type": "Ethertype", "ie_value": "Ethertype", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the Ethertype."})
ies.append({"ie_type": "C-TAG", "ie_value": "C-TAG", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the Customer-VLAN tag."})
ies.append({"ie_type": "S-TAG", "ie_value": "S-TAG", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the Service-VLAN tag."})
ies.append({"ie_type": "SDF Filter", "ie_value": "SDF Filter", "presence": "O", "tlv_more": "0",
            "comment": "If packet filtering is required, for Ethernet frames with Ethertype indicating IPv4 or IPv6 payload, this IE shall describe the IP Packet Filter Set.Several IEs with the same IE type may be present to represent a list of SDF filters."})
group_list["Ethernet Packet Filter"] = {"index": "232", "type": "132", "ies": ies}
ies = []
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the FAR among all the FARs configured for that PFCP session."})
ies.append({"ie_type": "Apply Action", "ie_value": "Apply Action", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the action to apply to the packets, See clauses 5.2.1 and 5.2.3."})
ies.append({"ie_type": "Forwarding Parameters", "ie_value": "Forwarding Parameters", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present when the Apply Action requests the packets to be forwarded. It may be present otherwise.When present, this IE shall contain the forwarding instructions to be applied by the UP function when the Apply Action requests the packets to be forwarded.See table 7.5.2.3-2."})
ies.append({"ie_type": "Duplicating Parameters", "ie_value": "Duplicating Parameters", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present when the Apply Action requests the packets to be duplicated. It may be present otherwise.When present, this IE shall contain the forwarding instructions to be applied by the UP function for the traffic to be duplicated, when the Apply Action requests the packets to be duplicated.Several IEs with the same IE type may be present to represent to duplicate the packets to different destinations. See NOTE 1.See table 7.5.2.3-3."})
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall contain the BAR ID of the BAR defining the buffering instructions to be applied by the UP function when the Apply Action requests the packets to be buffered. "})
group_list["Create FAR"] = {"index": "103", "type": "3", "ies": ies}
ies = []
ies.append({"ie_type": "Destination Interface", "ie_value": "Destination Interface", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the destination interface of the outgoing packet."})
ies.append({"ie_type": "Network Instance", "ie_value": "Network Instance", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall identify the Network instance towards which to send the outgoing packet. See NOTE 1."})
ies.append({"ie_type": "Redirect Information", "ie_value": "Redirect Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to enforce traffic redirection towards a redirect destination provided by the CP function. "})
ies.append({"ie_type": "Outer Header Creation", "ie_value": "Outer Header Creation", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to add one or more outer header(s) to the outgoing packet. If present, it shall contain the F-TEID of the remote GTP-U peer when adding a GTP-U/UDP/IP header, or the Destination IP address and/or Port Number when adding a UDP/IP header or an IP header or the C-TAG/S-TAG (for 5GC). See NOTE 2."})
ies.append(
    {"ie_type": "Transport Level Marking", "ie_value": "Transport Level Marking", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the UP function is required to mark the IP header with the DSCP marking as defined by IETFRFC2474[22]. When present for EPC, it shall contain the value of the DSCP in the TOS/Traffic Class field set based on the QCI, and optionally the ARP priority level, of the associated EPS bearer, as described in clause 5.10 of 3GPPTS23.214[2]. When present for 5GC, it shall contain the value of the DSCP in the TOS/Traffic Class field set based on the 5QI, the Priority Level (if explicitly signalled), and optionally the ARP priority level, of the associated QoS flow, as described in clause 5.8.2.7 of 3GPPTS23.501[28],"})
ies.append({"ie_type": "Forwarding Policy", "ie_value": "Forwarding Policy", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a specific forwarding policy is required to be applied to the packets. It shall be present if the Destination Interface IE is set to SGi-LAN / N6-LAN. It may be present if the Destination Interface is set to Core, Access, or CP-Function.  See NOTE 2.When present, it shall contain an Identifier of the Forwarding Policy locally configured in the UP function."})
ies.append({"ie_type": "Header Enrichment", "ie_value": "Header Enrichment", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the UP function indicated support of Header Enrichment of UL traffic. When present, it shall contain information for header enrichment."})
ies.append(
    {"ie_type": "Traffic Endpoint ID", "ie_value": "Linked Traffic Endpoint ID", "presence": "C", "tlv_more": "0",
     "comment": "This IE may be present, if it is available and the UP function indicated support of the PDI optimisation feature, (see clause 8.2.25). When present, it shall identify the Traffic Endpoint ID allocated for this PFCP session to receive the traffic in the reverse direction (see clause 5.2.3.1)."})
ies.append({"ie_type": "Proxying", "ie_value": "Proxying", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if proxying is to be performed by the UP function.When present, this IE shall contain the information that the UPF shall respond to Address Resolution Protocol and / or IPv6 Neighbour Solicitation based on the local cache information for the Ethernet PDUs."})
ies.append(
    {"ie_type": "3GPP Interface Type", "ie_value": "Destination Interface Type", "presence": "O", "tlv_more": "0",
     "comment": "This IE may be present to indicate the 3GPP interface type of the destination interface, if required by functionalities in the UP Function, e.g. for performance measurements."})
group_list["Forwarding Parameters"] = {"index": "104", "type": "4", "ies": ies}
ies = []
ies.append({"ie_type": "Destination Interface", "ie_value": "Destination Interface", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the destination interface of the outgoing packet."})
ies.append({"ie_type": "Outer Header Creation", "ie_value": "Outer Header Creation", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to add one or more outer header(s) to the outgoing packet. If present, it shall contain the F-TEID of the remote GTP-U peer. See NOTE 1."})
ies.append(
    {"ie_type": "Transport Level Marking", "ie_value": "Transport Level marking", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the UP function is required to mark the IP header with the DSCP marking as defined by IETFRFC2474[22]. When present, it shall contain the value of the DSCP in the TOS/Traffic Class field. "})
ies.append({"ie_type": "Forwarding Policy", "ie_value": "Forwarding Policy", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a specific forwarding policy is required to be applied to the packets. When present, it shall contain an Identifier of the Forwarding Policy locally configured in the UP function."})
group_list["Duplicating Parameters"] = {"index": "105", "type": "5", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the URR among all the URRs configured for this PFCP session."})
ies.append({"ie_type": "Measurement Method", "ie_value": "Measurement Method", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the method for measuring the network resources usage, i.e. whether the data volume, duration (i.e. time), combined volume/duration, or event shall be measured."})
ies.append({"ie_type": "Reporting Triggers", "ie_value": "Reporting Triggers", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the trigger(s) for reporting network resources usage to the CP function, e.g. periodic reporting or reporting upon reaching a threshold, or envelope closure."})
ies.append({"ie_type": "Measurement Period", "ie_value": "Measurement Period", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if periodic reporting is required. When present, it shall indicate the period for generating and reporting usage reports. "})
ies.append({"ie_type": "Volume Threshold", "ie_value": "Volume Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if volume-based measurement is used and reporting is required upon reaching a volume threshold. When present, it shall indicate the traffic volume value after which the UP function shall report network resources usage to the CP function for this URR."})
ies.append({"ie_type": "Volume Quota", "ie_value": "Volume Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if volume-based measurement is used and the CP function needs to provision a Volume Quota in the UP function (see clause 5.2.2.2)When present, it shall indicate the Volume Quota value."})
ies.append({"ie_type": "Event Threshold", "ie_value": "Event Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if event-based measurement is used and reporting is required upon reaching an event threshold. When present, it shall indicate the number of events after which the UP function shall report to the CP function for this URR."})
ies.append({"ie_type": "Event Quota", "ie_value": "Event Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if event-based measurement is used and the CP function needs to provision an Event Quota in the UP function (see clause 5.2.2.2)When present, it shall indicate the Event Quota value."})
ies.append({"ie_type": "Time Threshold", "ie_value": "Time Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if time-based measurement is used and reporting is required upon reaching a time threshold. When present, it shall indicate the time usage after which the UP function shall report network resources usage to the CP function for this URR."})
ies.append({"ie_type": "Time Quota", "ie_value": "Time Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if time-based measurement is used and the CP function needs to provision a Time Quota in the UP function (see clause 5.2.2.2)When present, it shall indicate the Time Quota value"})
ies.append({"ie_type": "Quota Holding Time", "ie_value": "Quota Holding Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, for a time, volume or event-based measurement, if reporting is required and packets are no longer permitted to pass on when no packets are received during a given inactivity period.When present, it shall contain the duration of the inactivity period."})
ies.append({"ie_type": "Dropped DL Traffic Threshold", "ie_value": "Dropped DL Traffic Threshold", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if reporting is required when the DL traffic being dropped exceeds a threshold.When present, it shall contain the threshold of the DL traffic being dropped."})
ies.append({"ie_type": "Quota Validity Time", "ie_value": "Quota Validity Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if reporting is required when the Quota Validity time for a given Quota is over."})
ies.append({"ie_type": "Monitoring Time", "ie_value": "Monitoring Time", "presence": "O", "tlv_more": "0",
            "comment": "When present, this IE shall contain the time at which the UP function shall re-apply the volume or time threshold. "})
ies.append({"ie_type": "Subsequent Volume Threshold", "ie_value": "Subsequent Volume Threshold", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be present if the Monitoring Time IE is present and volume-based measurement is used.When present, it shall indicate the traffic volume value after which the UP function shall report network resources usage to the CP function for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Subsequent Time Threshold", "ie_value": "Subsequent Time Threshold", "presence": "O", "tlv_more": "0",
     "comment": "This IE may be present if the Monitoring Time IE is present and time-based measurement is used.When present, it shall indicate the time usage after which the UP function shall report network resources usage to the CP function for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Subsequent Volume Quota", "ie_value": "Subsequent Volume Quota", "presence": "O", "tlv_more": "0",
     "comment": "This IE may be present if Monitoring Time IE is present and volume-based measurement is used (see clause 5.2.2.2).When present, it shall indicate the Volume Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Time Quota", "ie_value": "Subsequent Time Quota", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if Monitoring Time IE is present and time-based measurement is used (see clause 5.2.2.2)When present, it shall indicate the Time Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Event Threshold", "ie_value": "Subsequent Event Threshold", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE may be present if the Monitoring Time IE is present and event-based measurement is used.When present, it shall indicate the number of events after which the UP function shall report to the CP function for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Event Quota", "ie_value": "Subsequent Event Quota", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if Monitoring Time IE is present and event-based measurement is used (see clause 5.2.2.2).When present, it shall indicate the Event Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Inactivity Detection Time", "ie_value": "Inactivity Detection Time", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if time-based measurement is used and the time measurement need to be suspended when no packets are received during a given inactivity period. When present, it shall contain the duration of the inactivity period."})
ies.append({"ie_type": "Linked URR ID", "ie_value": "Linked URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if linked usage reporting is required. When present, this IE shall contain the linked URR ID which is related with this URR (see clause 5.2.2.4).Several IEs with the same IE type may be present to represent multiple linked URRs which are related with this URR."})
ies.append(
    {"ie_type": "Measurement Information", "ie_value": "Measurement Information", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be included if any of the following flag is set to 1.Applicable flags are:-	Measurement Before QoS Enforcement Flag: this flag shall be set to 1 if the traffic usage before any QoS Enforcement is requested to be measured.-	Inactive Measurement Flag: this flag shall be set to 1 if the measurement shall be paused (inactive). The measurement shall be performed (active) if the bit is set to 0 or if the Measurement Information IE is not present in the Create URR IE.-	Reduced Application Detection Information Flag: this flag may be set to 1, if the Reporting Triggers request to report the start or stop of application, to request the UP function to only report the Application ID in the Application Detection Information, e.g. for envelope reporting.-	Immediate Start Time Metering Flag: this flag may be set to 1 if time-based measurement is used and the UP function is requested to start the time metering immediately at receiving the flag. .-	Measurement of Number of Packets Flag: this flag may be set to 1 when the Volume-based measurement applies, to request the UP function to report the number of packets in UL/DL/Total in addition to the measurement in octet."})
ies.append({"ie_type": "Time Quota Mechanism", "ie_value": "Time Quota Mechanism", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if time-based measurement based on CTP or DTP is used."})
ies.append({"ie_type": "Aggregated URRs", "ie_value": "Aggregated URRs", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the URR is used to support a Credit Pool.Several IEs with the same IE type may be present to provide multiple aggregated URRs."})
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID for Quota Action", "presence": "C", "tlv_more": "0",
            "comment": "This IE may be present if the Volume Quota IE and/or the Time Quota IE and/or Event Quota IE is provisioned in the URR and the UP Function indicated support of the Quota Action feature.When present, it shall contain the identifier of the substitute FAR the UP function shall apply, for the traffic associated to this URR, when exhausting any of these quotas. See NOTE 1. "})
ies.append(
    {"ie_type": "Ethernet Inactivity Timer", "ie_value": "Ethernet Inactivity Timer", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if Ethernet traffic reporting is used and the SMF requests the UP function to also report inactive UE MAC addresses.When present, it shall contain the duration of the Ethernet inactivity period."})
ies.append({"ie_type": "Additional Monitoring Time", "ie_value": "Additional Monitoring Time", "presence": "O",
            "tlv_more": "0",
            "comment": "When present, this IE shall contain the time at which the UP function shall re-apply the volume or time or event threshold/quota provisioned in the IE.Several IEs with the same IE type may be present to provide multiple Monitoring Times."})
group_list["Create URR"] = {"index": "106", "type": "6", "ies": ies}
ies = []
ies.append({"ie_type": "QER ID", "ie_value": "QER ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the QER among all the QER configured for that PFCP session"})
ies.append({"ie_type": "QER Correlation ID", "ie_value": "QER Correlation ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to correlate the QERs of several PFCP sessions, for APN-AMBR enforcement of multiple UEs PDN connections to the same APN."})
ies.append({"ie_type": "Gate Status", "ie_value": "Gate Status", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate whether the packets are allowed to be forwarded (the gate is open) or shall be discarded (the gate is closed) in the uplink and/or downlink directions."})
ies.append({"ie_type": "MBR", "ie_value": "Maximum Bitrate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if an MBR enforcement action shall be applied to packets matching this PDR. When present, this IE shall indicate the uplink and/or downlink maximum bit rate to be enforced for packets matching the PDR.For EPC, this IE may be set to the value of:-	the APN-AMBR, for a QER that is referenced by all the PDRs of the non-GBR bearers of a PDN connection;-	the TDF session MBR, for a QER that is referenced by all the PDRs of a TDF session;-	the bearer MBR, for a QER that is referenced by all the PDRs of a bearer;-	the SDF MBR, for a QER that is referenced by all the PDRs of a SDF.For 5GC, this IE may be set to the value of:-	the Session-AMBR, for a QER that is referenced by all the PDRs of the non-GBR QoS flows of a PDU session;-	the QoS Flow MBR, for a QER that is referenced by all the PDRs of a QoS Flow;-	the SDF MBR, for a QER that is referenced by all the PDRs of a SDF."})
ies.append({"ie_type": "GBR", "ie_value": "Guaranteed Bitrate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a GBR has been authorized to packets matching this PDR. When present, this IE shall indicate the authorized uplink and/or downlink guaranteed bit rate.This IE may be set to the value of:-	the aggregate GBR, for a QER that is referenced by all the PDRs of a GBR bearer;-	the QoS Flow GBR, for a QER that is referenced by all the PDRs of a QoS Flow (for 5GC);-	the SDF GBR, for a QER that is referenced by all the PDRs of a SDF."})
ies.append({"ie_type": "Packet Rate", "ie_value": "Packet Rate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a Packet Rate enforcement action (in terms of number of packets per time interval) shall be applied to packets matching this PDR.When present, this IE shall indicate the uplink and/or downlink maximum packet rate to be enforced for packets matching the PDR.This IE may be set to the value of:-	downlink packet rate for Serving PLMN Rate Control, for a QER that is referenced by all PDRs of the UE belonging to the PDN connection using CIoT EPS Optimizations as described in 3GPPTS23.401[2]);-	uplink and/or downlink packet rate for APN Rate Control, for a QER that is referenced by all the PDRs of the UE belonging to PDN connections to the same APN using CIoT EPS Optimizations as described in 3GPPTS23.401[2])."})
ies.append({"ie_type": "DL Flow Level Marking", "ie_value": "DL Flow Level Marking", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be set if the UP function is required to mark the packets for QoS purposes:-	by the TDF-C, for DL flow level marking for application indication (see clause 5.4.5);-	by the PGW-C, for setting the GTP-U Service Class Indicator extension header for service indication towards GERAN (see clause 5.4.12)."})
ies.append({"ie_type": "QFI", "ie_value": "QoS flow identifier", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the QoS flow identifier shall be inserted by the UPF."})
ies.append({"ie_type": "RQI", "ie_value": "Reflective QoS", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function is required to insert a Reflective QoS Identifier to request reflective QoS for uplink traffic."})
ies.append(
    {"ie_type": "Paging Policy Indicator", "ie_value": "Paging Policy Indicator", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the UPF is required to set the Paging Policy Indicator (PPI) in outgoing packets (see clause 5.4.3.2 of 3GPPTS23.501[28]).When present, it shall be set to the PPI value to set. "})
ies.append({"ie_type": "Averaging Window", "ie_value": "Averaging Window", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the UP function is required to use a different Averaging window than the default one. (NOTE)"})
group_list["Create QER"] = {"index": "107", "type": "7", "ies": ies}
ies = []
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the BAR provisioned for that PFCP session."})
ies.append(
    {"ie_type": "Downlink Data Notification Delay", "ie_value": "Downlink Data Notification Delay", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE shall be present if the UP function indicated support of the Downlink Data Notification Delay parameter (see clause 8.2.28) and the UP function has to delay the notification to the CP function about the arrival of DL data packets.When present, it shall contain the delay the UP function shall apply between receiving a downlink data packet and notifying the CP function about it, when the Apply Action parameter requests to buffer the packets and notify the CP function."})
ies.append(
    {"ie_type": "Suggested Buffering Packets Count", "ie_value": "Suggested Buffering Packets Count", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE may be present if the UP Function indicated support of the the feature UDBC.When present, it shall contain the number of packets that are suggested to be buffered when the Apply Action parameter requests to buffer the packets. The packets that exceed the limit shall be discarded."})
group_list["Create BAR"] = {"index": "185", "type": "85", "ies": ies}
ies = []
ies.append({"ie_type": "Traffic Endpoint ID", "ie_value": "Traffic Endpoint ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the Traffic Endpoint for that Sx session."})
ies.append({"ie_type": "F-TEID", "ie_value": "Local F-TEID", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the local F-TEID to match for an incoming packet.The CP function shall set the CHOOSE (CH) bit to 1 if the UP function supports the allocation of F-TEID and the CP function requests the UP function to assign a local F-TEID to the Traffic Endpoint."})
ies.append({"ie_type": "Network Instance", "ie_value": "Network Instance", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall be present if the CP function requests the UP function to allocate a UE IP address/prefix.If present, this IE shall identify the Network instance to match for the incoming packet. See NOTE 1, NOTE2."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP address", "presence": "O", "tlv_more": "0",
            "comment": "If present, this IE shall identify the source or destination IP address to match for the incoming packet. (NOTE 3)The CP function shall set the CHOOSE (CH) bit to 1 if the UP function supports the allocation of UE IP address/ prefix and the CP function requests the UP function to assign a UE IP address/prefix to the Traffic Endpoint."})
ies.append(
    {"ie_type": "Ethernet PDU Session Information", "ie_value": "Ethernet PDU Session Information", "presence": "O",
     "tlv_more": "0",
     "comment": "This IE may be present to identify all the (DL) Ethernet packets matching an Ethernet PDU session (see clause 5.13.1)."})
ies.append({"ie_type": "Framed-Route", "ie_value": "Framed-Route", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe a framed route.Several IEs with the same IE type may be present to provision a list of framed routes. (NOTE 3)"})
ies.append({"ie_type": "Framed-Routing", "ie_value": "Framed-Routing", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe the framed routing associated to a framed route. "})
ies.append({"ie_type": "Framed-IPv6-Route", "ie_value": "Framed-IPv6-Route", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present for a DL PDR if the UPF indicated support of Framed Routing (see clause 8.2.25). If present, this IE shall describe a framed IPv6 route.Several IEs with the same IE type may be present to provision a list of framed IPv6 routes. (NOTE 3)"})
ies.append({"ie_type": "QFI", "ie_value": "QFI", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the UPF has indicated it supports MTE feature as specified in clause 8.2.25.If present, this IE shall identify the QoS Flow Identifier to match for the incoming packet received from the traffic endpoint.Several IEs with the same IE type may be present to provision a list of QFIs. When present, the full set of applicable QFIs shall be provided."})
group_list["Create Traffic Endpoint"] = {"index": "227", "type": "127", "ies": ies}
ies = []
ies.append({"ie_type": "MAR ID", "ie_value": "MAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the MAR among all the MARs configured for that PFCP session."})
ies.append({"ie_type": "Steering Functionality", "ie_value": "Steering Functionality", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall be present to indicate the applicable traffic steering functionality."})
ies.append({"ie_type": "Steering Mode", "ie_value": "Steering Mode", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall be present to indicate the steering mode."})
ies.append({"ie_type": "Access Forwarding Action Information 1", "ie_value": "Access Forwarding Action Information 1",
            "presence": "M", "tlv_more": "0",
            "comment": "This IE shall be present to provision access specific (non-3gpp or 3gpp) forwarding action information."})
ies.append({"ie_type": "Access Forwarding Action Information 2", "ie_value": "Access Forwarding Action Information 2",
            "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present to provision access specific (non-3gpp or 3gpp) forwarding action information if the UE is registered for both non-3GPP and 3GPP accesses."})
group_list["Create MAR"] = {"index": "265", "type": "165", "ies": ies}
ies = []
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the FAR among all the FARs configured for this PFCP session. "})
ies.append({"ie_type": "Weight", "ie_value": "Weight", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if steering mode is set to Load Balancing to identify the weight of the FAR.(NOTE 1) "})
ies.append({"ie_type": "Priority", "ie_value": "Priority", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the steering mode is set to Active-Standby or Priority-based. (NOTE 2)"})
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the URR among all the URRs configured for the PFCP session. This enables the SMF to request separate usage reports for different FARs (i.e. different accesses) (NOTE 3)Several IEs within the same IE type may be present to represent a list of URRs to be associated to the FAR."})
group_list["Access Forwarding Action Information 1"] = {"index": "266", "type": "166", "ies": ies}
group_list["Access Forwarding Action Information 2"] = {"index": "267", "type": "167", "ies": ies}
ies = []
ies.append({"ie_type": "PDR ID", "ie_value": "PDR ID", "presence": "M", "tlv_more": "0", "comment": ""})
ies.append({"ie_type": "F-TEID", "ie_value": "Local F-TEID", "presence": "C", "tlv_more": "0",
            "comment": "If the UP function allocates the F-TEID, this IE shall be present and shall contain the local F-TEID to be used for this PDR."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP Address", "presence": "C", "tlv_more": "0",
            "comment": "If the UP function allocates the UE IP address/prefix, this IE shall be present and shall contain the UE IP address/ prefix assigned by the UP function."})
group_list["Created PDR"] = {"index": "108", "type": "8", "ies": ies}
ies = []
ies.append({"ie_type": "Sequence Number", "ie_value": "Load Control Sequence Number", "presence": "M", "tlv_more": "0",
            "comment": "See clause 6.2.3.3.2 for the description and use of this parameter."})
ies.append({"ie_type": "Metric", "ie_value": "Load Metric", "presence": "M", "tlv_more": "0",
            "comment": "See clause 6.2.3.3.2 for the description and use of this parameter."})
group_list["Load Control Information"] = {"index": "151", "type": "51", "ies": ies}
ies = []
ies.append(
    {"ie_type": "Sequence Number", "ie_value": "Overload Control Sequence Number", "presence": "M", "tlv_more": "0",
     "comment": "See clause 6.2.4.3.2 for the description and use of this parameter."})
ies.append({"ie_type": "Metric", "ie_value": "Overload Reduction Metric", "presence": "M", "tlv_more": "0",
            "comment": "See clause 6.2.4.3.2 for the description and use of this parameter."})
ies.append({"ie_type": "Timer", "ie_value": "Period of Validity", "presence": "M", "tlv_more": "0",
            "comment": "See clause 6.2.4.3.2 for the description and use of this parameter."})
ies.append({"ie_type": "OCI Flags", "ie_value": "Overload Control Information Flags", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if any of flag in this IE is set.  "})
group_list["Overload Control Information"] = {"index": "154", "type": "54", "ies": ies}
ies = []
ies.append({"ie_type": "Traffic Endpoint ID", "ie_value": "Traffic Endpoint ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the Traffic Endpoint for that Sx session."})
ies.append({"ie_type": "F-TEID", "ie_value": "Local F-TEID", "presence": "C", "tlv_more": "0",
            "comment": "If the UP function allocates the F-TEID, this IE shall be present and shall contain the local F-TEID to be used for this Traffic Endpoint."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP Address", "presence": "C", "tlv_more": "0",
            "comment": "If the UP function allocates the UE IP address/prefix, this IE shall be present and shall contain the UE IP address/ prefix assigned by the UP function."})
group_list["Created Traffic Endpoint"] = {"index": "228", "type": "128", "ies": ies}
ies = []
ies.append({"ie_type": "PDR ID", "ie_value": "PDR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the PDR among all the PDRs configured for that PFCP session."})
ies.append({"ie_type": "Outer Header Removal", "ie_value": "Outer Header Removal", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it needs to be changed."})
ies.append({"ie_type": "Precedence", "ie_value": "Precedence", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if there is a change in the PDRs precedence to be applied by the UP function among all PDRs of the PFCP session, when looking for a PDR matching an incoming packet."})
ies.append({"ie_type": "PDI", "ie_value": "PDI", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if there is a change within the PDI against which incoming packets will be matched. When present, this IE shall replace the PDI previously stored in the UP function for this PDR. See Table 7.5.2.2-2."})
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it needs to be changed"})
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a measurement action shall be applied or no longer applied to packets matching this PDR.When present, this IE shall contain the list of all the URR IDs to be associated to the PDR."})
ies.append({"ie_type": "QER ID", "ie_value": "QER ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a QoS enforcement action shall be applied or no longer applied to packets matching this PDR.When present, this IE shall contain the list of all the QER IDs to be associated to the PDR."})
ies.append(
    {"ie_type": "Activate Predefined Rules", "ie_value": "Activate Predefined Rules", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if new Predefined Rule(s) needs to be activated for the PDR. When present this IE shall contain one Predefined Rules name.Several IEs with the same IE type may be present to represent multiple Activate Predefined Rules names."})
ies.append({"ie_type": "Deactivate Predefined Rules", "ie_value": "Deactivate Predefined Rules", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if Predefined Rule(s) needs to be deactivated for the PDR. When present this IE shall contain one Predefined Rules name.Several IEs with the same IE type may be present to represent multiple Activate Predefined Rules names."})
ies.append({"ie_type": "Activation Time", "ie_value": "Activation Time", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the PDR activation time shall be changed. (NOTE 2)"})
ies.append({"ie_type": "Deactivation Time", "ie_value": "Deactivation Time", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the PDR deactivation time shall be changed. (NOTE 2)"})
group_list["Update PDR"] = {"index": "109", "type": "9", "ies": ies}
ies = []
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the FAR to be updated."})
ies.append({"ie_type": "Apply Action", "ie_value": "Apply Action", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed."})
ies.append({"ie_type": "Update Forwarding Parameters", "ie_value": "Update Forwarding parameters", "presence": "C",
            "tlv_more": "0", "comment": "This IE shall be present if it is changed.See table 7.5.4.3-2."})
ies.append({"ie_type": "Update Duplicating Parameters", "ie_value": "Update Duplicating Parameters", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if it is changed. See table 7.5.4.3-3.Several IEs with the same IE type may be present to request to duplicate the packets to different destinations."})
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the BAR ID associated to the FAR needs to be modified. "})
group_list["Update FAR"] = {"index": "110", "type": "10", "ies": ies}
ies = []
ies.append({"ie_type": "Destination Interface", "ie_value": "Destination Interface", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed.When present, it shall indicate the destination interface of the outgoing packet."})
ies.append({"ie_type": "Network Instance", "ie_value": "Network instance", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed."})
ies.append({"ie_type": "Redirect Information", "ie_value": "Redirect Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the instructions regarding the redirection of traffic by the UP function need to be modified."})
ies.append({"ie_type": "Outer Header Creation", "ie_value": "Outer Header Creation", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed. SeeNOTE1."})
ies.append(
    {"ie_type": "Transport Level Marking", "ie_value": "Transport Level Marking", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall only be provided if it is changed"})
ies.append({"ie_type": "Forwarding Policy", "ie_value": "Forwarding Policy", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed. SeeNOTE1."})
ies.append({"ie_type": "Header Enrichment", "ie_value": "Header Enrichment", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed"})
ies.append({"ie_type": "PFCPSMReq-Flags", "ie_value": "PFCPSMReq-Flags", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if at least one of the flags is set to 1.-	SNDEM (Send End Marker Packets): this IE shall be present if the CP function modifies the F-TEID of the downstream node in the Outer Header Creation IE and the CP function requests the UP function to construct and send GTP-U End Marker messages towards the old F-TEID of the downstream node. "})
ies.append(
    {"ie_type": "Traffic Endpoint ID", "ie_value": "Linked Traffic Endpoint ID", "presence": "C", "tlv_more": "0",
     "comment": "This IE may be present, if it is changed and the UP function indicated support of the PDI optimization feature, (see clause 8.2.25). When present, it shall identify the Traffic Endpoint ID allocated for this PFCP session to receive the traffic in the reverse direction (see clause 5.2.3.1)."})
ies.append(
    {"ie_type": "3GPP Interface Type", "ie_value": "Destination Interface Type", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present to indicate the 3GPP interface type of the destination interface, if the value has changed."})
group_list["Update Forwarding Parameters"] = {"index": "111", "type": "11", "ies": ies}
ies = []
ies.append({"ie_type": "Destination Interface", "ie_value": "Destination Interface", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed.When present, it shall indicate the destination interface of the outgoing packet."})
ies.append({"ie_type": "Outer Header Creation", "ie_value": "Outer Header Creation", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed. SeeNOTE1."})
ies.append(
    {"ie_type": "Transport Level Marking", "ie_value": "Transport Level Marking", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall only be provided if it is changed."})
ies.append({"ie_type": "Forwarding Policy", "ie_value": "Forwarding Policy", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall only be provided if it is changed. SeeNOTE1."})
group_list["Update Duplicating Parameters"] = {"index": "205", "type": "105", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the URR among all the URRs configured for that PFCP session"})
ies.append({"ie_type": "Measurement Method", "ie_value": "Measurement Method", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the measurement method needs to be modified.When present, this IE shall indicate the method for measuring the network resources usage, i.e. whether the data volume, duration (i.e. time), combined volume/duration, or event shall be measured."})
ies.append({"ie_type": "Reporting Triggers", "ie_value": "Reporting Triggers", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the reporting triggers needs to be modified.When present, this IE shall indicate the trigger(s) for reporting network resources usage to the CP function, e.g. periodic reporting or reporting upon reaching a threshold, or envelope closure."})
ies.append({"ie_type": "Measurement Period", "ie_value": "Measurement Period", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Measurement Period needs to be modified.When present, it shall indicate the period for generating and reporting usage reports. "})
ies.append({"ie_type": "Volume Threshold", "ie_value": "Volume Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Volume Threshold needs to be modified. When present, it shall indicate the traffic volume value after which the UP function shall report network resources usage to the CP function for this URR."})
ies.append({"ie_type": "Volume Quota", "ie_value": "Volume Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Volume Quota needs to be modified.When present, it shall indicate the Volume Quota value."})
ies.append({"ie_type": "Time Threshold", "ie_value": "Time Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Time Threshold needs to be modified. When present, it shall indicate the time usage after which the UP function shall report network resources usage to the CP function for this URR."})
ies.append({"ie_type": "Time Quota", "ie_value": "Time Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Time Quota needs to be modified.When present, it shall indicate the Time Quota value."})
ies.append({"ie_type": "Event Threshold", "ie_value": "Event Threshold", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if Event Threshold needs to be modified.When present, it shall indicate the number of events after which the UP function shall report to the CP function for this URR."})
ies.append({"ie_type": "Event Quota", "ie_value": "Event Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if Event Quota needs to be modified.When present, it shall indicate the Event Quota value."})
ies.append({"ie_type": "Quota Holding Time", "ie_value": "Quota Holding Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Quota Holding Time needs to be modified.When present, it shall contain the duration of the Quota Holding Time."})
ies.append({"ie_type": "Dropped DL Traffic Threshold", "ie_value": "Dropped DL Traffic Threshold", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if the Dropped DL Threshold needs to be modified.When present, it shall contain the threshold of the DL traffic being dropped."})
ies.append({"ie_type": "Quota Validity Time", "ie_value": "Quota Validity Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if Quota Validity time was not sent earlier or quota validity time value needs to be modified."})
ies.append({"ie_type": "Monitoring Time", "ie_value": "Monitoring Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Monitoring Time needs to be modified. When present, this IE shall contain the time at which the UP function shall re-apply the volume or time threshold. "})
ies.append({"ie_type": "Subsequent Volume Threshold", "ie_value": "Subsequent Volume Threshold", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if the Subsequent Volume Threshold needs to be modified and volume-based measurement is used.When present, it shall indicate the traffic volume value after which the UP function shall report network resources usage to the CP function for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Subsequent Time Threshold", "ie_value": "Subsequent Time Threshold", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Subsequent Time Threshold needs to be modified. When present, it shall indicate the time usage value after which the UP function shall report network resources usage to the CP function for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Subsequent Volume Quota", "ie_value": "Subsequent Volume Quota", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Subsequent Volume Quota needs to be modified.When present, it shall indicate the Volume Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Time Quota", "ie_value": "Subsequent Time Quota", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Subsequent Time Quota needs to be modified.When present, it shall indicate the Time Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Event Threshold", "ie_value": "Subsequent Event Threshold", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE shall be present if the Subsequent Event Threshold needs to be modified.When present, it shall indicate the number of events after which the UP function shall report to the CP function for this URR for the period after the Monitoring Time."})
ies.append({"ie_type": "Subsequent Event Quota", "ie_value": "Subsequent Event Quota", "presence": "O", "tlv_more": "0",
            "comment": "This IE shall be present if the Subsequent Event Quota needs to be modified.When present, it shall indicate the Event Quota value which the UP function shall use for this URR for the period after the Monitoring Time."})
ies.append(
    {"ie_type": "Inactivity Detection Time", "ie_value": "Inactivity Detection Time", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Inactivity Detection Time needs to be modified.When present, it shall indicate the duration of the inactivity period after which time measurement needs to be suspended when no packets are received during this inactivity period. "})
ies.append({"ie_type": "Linked URR ID", "ie_value": "Linked URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if linked usage reporting is required. When present, this IE shall contain the linked URR ID which is related with this URR (see clause 5.2.2.4).Several IEs with the same IE type may be present to represent multiple linked URRs which are related with this URR."})
ies.append(
    {"ie_type": "Measurement Information", "ie_value": "Measurement Information", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be included if any of the following flag is set to 1.Applicable flags are:-	Inactive Measurement Flag: this flag shall be set to 1 if the measurement shall be paused (inactive). The measurement shall be performed (active) if the bit is set to 0 or if the Measurement Information IE is not present in the Update URR IE.-	Reduced Application Detection Information Flag: this flag may be set to 1, if the Reporting Triggers request to report the start or stop of application, to request the UP function to only report the Application ID in the Application Detection Information, e.g. for envelope reporting.-	Immediate Start Time Metering Flag: this flag may be set to 1 if time-based measurement is used and the UP function is requested to start the time metering immediately at receiving the flag."})
ies.append({"ie_type": "Time Quota Mechanism", "ie_value": "Time Quota Mechanism", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if time-based measurement based on CTP or DTP needs to be modified."})
ies.append({"ie_type": "Aggregated URRs", "ie_value": "Aggregated URRs", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the Aggregated URRs IE needs to be modified. See Table 7.5.2.4-2.Several IEs with the same IE type may be present to provision multiple aggregated URRs.When present, this IE shall provide the complete list of the aggregated URRs."})
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID for Quota Action", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the FAR ID for Quota Action IE needs to be modified. This IE may be present if the Volume Quota IE or the Time Quota IE or Event Quota IE is newly provisioned in the URR and the UP Function indicated support of the Quota Action.When present, it shall contain the identifier of the substitute FAR the UP function shall apply, for the traffic associated to this URR, when exhausting any of these quotas. See NOTE 1. "})
ies.append(
    {"ie_type": "Ethernet Inactivity Timer", "ie_value": "Ethernet Inactivity Timer", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the Ethernet Inactivity Timer needs to be modified. When present, it shall contain the duration of the Ethernet inactivity period."})
ies.append({"ie_type": "Additional Monitoring Time", "ie_value": "Additional Monitoring Time", "presence": "O",
            "tlv_more": "0",
            "comment": "This IE shall be present if the additional Monitoring Time needs to be modified. When present, this IE shall contain the time at which the UP function shall re-apply the volume or time or event threshold/quota. See Table 7.5.2.4-3.The CP function shall provide the full set of Additional Monitoring Times IE(s). The UP function shall replace any Additional Monitoring Times IE(s) provisioned earlier by the new set of received IE(s)."})
group_list["Update URR"] = {"index": "113", "type": "13", "ies": ies}
ies = []
ies.append({"ie_type": "QER ID", "ie_value": "QER ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the QER among all the QRs configured for that PFCP session"})
ies.append({"ie_type": "QER Correlation ID", "ie_value": "QER Correlation ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the QER correlation ID in this QER needs to be modified.See NOTE 1."})
ies.append({"ie_type": "Gate Status", "ie_value": "Gate Status", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Gate Status needs to be modified. When present, it shall indicate whether the packets are allowed to be forwarded (the gate is open) or shall be discarded (the gate is closed) in the uplink and/or downlink directions.See NOTE 1."})
ies.append({"ie_type": "MBR", "ie_value": "Maximum Bitrate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if an MBR enforcement action applied to packets matching this PDR need to be modified.When present, this IE shall indicate the uplink and/or downlink maximum bit rate to be enforced for packets matching the PDR.For EPC, this IE may be set to the value of:-	the APN-AMBR, for a QER that is referenced by all the PDRs of the non-GBR bearers of a PDN connection;-	the TDF session MBR, for a QER that is referenced by all the PDRs of a TDF session;-	the bearer MBR, for a QER that is referenced by all the PDRs of a bearer;-	the SDF MBR, for a QER that is referenced by all the PDRs of a SDF.For 5GC, this IE may be set to the value of:-	the Session-AMBR, for a QER that is referenced by all the PDRs of the non-GBR QoS flows of a PDU session;-	the QoS Flow MBR, for a QER that is referenced by all the PDRs of a QoS Flow;-	the SDF MBR, for a QER that is referenced by all the PDRs of a SDF.See NOTE 1."})
ies.append({"ie_type": "GBR", "ie_value": "Guaranteed Bitrate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a GBR authorization to packets matching this PDR needs to be modified. When present, this IE shall indicate the authorized uplink and/or downlink guaranteed bit rate.This IE may be set to the value of:-	the aggregate GBR, for a QER that is referenced by all the PDRs of a GBR bearer;-	the QoS Flow GBR, for a QER that is referenced by all the PDRs of a QoS Flow (for 5GC);-	the SDF GBR, for a QER that is referenced by all the PDRs of a SDF.See NOTE 1."})
ies.append({"ie_type": "Packet Rate", "ie_value": "Packet Rate", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a Packet Rate enforcement action (in terms of number of packets per time interval) need to be modified for packets matching this PDR. "})
ies.append({"ie_type": "DL Flow Level Marking", "ie_value": "DL Flow Level Marking", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be set if the DL Flow Level Marking IE needs to be modified.See NOTE 1."})
ies.append({"ie_type": "QFI", "ie_value": "QoS flow identifier", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it needs to be modified."})
ies.append({"ie_type": "RQI", "ie_value": "Reflective QoS", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it needs to be modified."})
ies.append(
    {"ie_type": "Paging Policy Indicator", "ie_value": "Paging Policy Indicator", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if it needs to be modified."})
ies.append({"ie_type": "Averaging Window", "ie_value": "Averaging Window", "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if the UP function is required to modify the Averaging Window. (NOTE 2)"})
group_list["Update QER"] = {"index": "114", "type": "14", "ies": ies}
ies = []
ies.append({"ie_type": "PDR ID", "ie_value": "PDR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify  the PDR to be deleted."})
group_list["Remove PDR"] = {"index": "115", "type": "15", "ies": ies}
ies = []
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the FAR to be deleted."})
group_list["Remove FAR"] = {"index": "116", "type": "16", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the URR to be deleted."})
group_list["Remove URR"] = {"index": "117", "type": "17", "ies": ies}
ies = []
ies.append({"ie_type": "QER ID", "ie_value": "QER ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the QER to be deleted."})
group_list["Remove QER"] = {"index": "118", "type": "18", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the URR being queried."})
group_list["Query URR"] = {"index": "177", "type": "77", "ies": ies}
ies = []
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the BAR Rule to be modified."})
ies.append(
    {"ie_type": "Downlink Data Notification Delay", "ie_value": "Downlink Data Notification Delay", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE shall be present if the UP function indicated support of the Downlink Data Notification Delay parameter (see clause 8.2.28) and the Downlink Data Notification Delay needs to be modified.When present, it shall contain the delay the UP function shall apply between receiving a downlink data packet and notifying the CP function about it, when the Apply Action parameter requests to buffer the packets and notify the CP function."})
ies.append(
    {"ie_type": "Suggested Buffering Packets Count", "ie_value": "Suggested Buffering Packets Count", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE may be present if the UP Function indicated support of the the feature UDBC.When present, it shall contain the number of packets that are suggested to be buffered when the Apply Action parameter requests to buffer the packets. The packets that exceed the limit shall be discarded."})
group_list["Update BAR Session Modification Request"] = {"index": "186", "type": "86", "ies": ies}
ies = []
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the BAR to be deleted."})
group_list["Remove BAR"] = {"index": "187", "type": "87", "ies": ies}
ies = []
ies.append({"ie_type": "Traffic Endpoint ID", "ie_value": "Traffic Endpoint ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the Traffic Endpoint to be deleted."})
group_list["Remove Traffic Endpoint"] = {"index": "230", "type": "130", "ies": ies}
ies = []
ies.append({"ie_type": "MAR ID", "ie_value": "MAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the MAR to be deleted."})
group_list["Remove MAR"] = {"index": "268", "type": "168", "ies": ies}
ies = []
ies.append({"ie_type": "MAR ID", "ie_value": "MAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the MAR to be updated."})
ies.append({"ie_type": "Steering Functionality", "ie_value": "Steering Functionality", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed."})
ies.append({"ie_type": "Steering Mode", "ie_value": "Steering Mode", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed."})
ies.append({"ie_type": "Update Access Forwarding Action Information 1",
            "ie_value": "Update Access Forwarding Action Information 1", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Access Forwarding Action Information 1 was provisioned previously and if any of IEs is to be changed.This IE shall also be present to remove Access Forwarding Action Information 1 that was provisioned previously if the UE deregisters from the corresponding access. This shall be done by including this IE with a null length."})
ies.append({"ie_type": "Update Access Forwarding Action Information 2",
            "ie_value": "Update Access Forwarding Action Information 2", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the Access Forwarding Action Information 2 was provisioned previously and if any of IEs is to be changed.This IE shall also be present to remove Access Forwarding Action Information 2 that was provisioned previously if the UE deregisters from the corresponding access. This shall be done by including this IE with a null length."})
ies.append({"ie_type": "Access Forwarding Action Information 1", "ie_value": "Access Forwarding Action Information 1",
            "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present to provision access specific (non-3gpp or 3gpp) forwarding action information when another access is added, i.e. when the UE is registered in both non-3GPP and 3GPP accesses.See Table 7.5.2.8-2. "})
ies.append({"ie_type": "Access Forwarding Action Information 2", "ie_value": "Access Forwarding Action Information 2",
            "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present to provision access specific (non-3gpp or 3gpp) forwarding action information when another access is added, i.e. when the UE is registered in both non-3GPP and 3GPP accesses.See Table 7.5.2.8-3. "})
group_list["Update MAR"] = {"index": "269", "type": "169", "ies": ies}
ies = []
ies.append({"ie_type": "FAR ID", "ie_value": "FAR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed. "})
ies.append({"ie_type": "Weight", "ie_value": "Weight", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed."})
ies.append({"ie_type": "Priority", "ie_value": "Priority", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if it is changed."})
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a measurement action shall be applied or no longer applied to packets for this access.When present, this IE shall contain the list of all the URR IDs to be associated to this access."})
group_list["Update Access Forwarding Action Information 1"] = {"index": "275", "type": "175", "ies": ies}
group_list["Update Access Forwarding Action Information 2"] = {"index": "276", "type": "176", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the URR for which usage is reported."})
ies.append({"ie_type": "UR-SEQN", "ie_value": "UR-SEQN", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the Usage Report for the URR (see clause 5.2.2.3)."})
ies.append({"ie_type": "Usage Report Trigger", "ie_value": "Usage Report Trigger", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the trigger for this report."})
ies.append({"ie_type": "Start Time", "ie_value": "Start Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was started."})
ies.append({"ie_type": "End Time", "ie_value": "End Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was generated."})
ies.append({"ie_type": "Volume Measurement", "ie_value": "Volume Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a volume measurement needs to be reported."})
ies.append({"ie_type": "Duration Measurement", "ie_value": "Duration Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a duration measurement needs to be reported."})
ies.append({"ie_type": "Time of First Packet", "ie_value": "Time of First Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Time of Last Packet", "ie_value": "Time of Last Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Usage Information", "ie_value": "Usage Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function reports Usage Reports before and after a Monitoring Time or before and after QoS enforcement. When present, it shall indicate whether the usage is reported for the period before or after that time, or before or after QoS enforcement."})
ies.append({"ie_type": "Query URR Reference", "ie_value": "Query URR Reference", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if this usage report is sent as a result of a query URR received in an PFCP Session Modification Request and the Query URR Reference IE was present in the PFCP Session Modification Request.When present, it shall be set to the Query URR Reference value received in the PFCP Session Modification Request. "})
ies.append({"ie_type": "Ethernet Traffic Information", "ie_value": "Ethernet Traffic Information", "presence": "C",
            "tlv_more": "0",
            "comment": " This IE shall be present if Ethernet Traffic Information needs to be reported. "})
group_list["Usage Report Session Modification Response"] = {"index": "178", "type": "78", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the URR for which usage is reported."})
ies.append({"ie_type": "UR-SEQN", "ie_value": "UR-SEQN", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the Usage Report for the URR (see clause 5.2.2.3)."})
ies.append({"ie_type": "Usage Report Trigger", "ie_value": "Usage Report Trigger", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the trigger for this report."})
ies.append({"ie_type": "Start Time", "ie_value": "Start Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was started."})
ies.append({"ie_type": "End Time", "ie_value": "End Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was generated."})
ies.append({"ie_type": "Volume Measurement", "ie_value": "Volume Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a volume needs to be reported."})
ies.append({"ie_type": "Duration Measurement", "ie_value": "Duration Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a duration measurement needs to be reported."})
ies.append({"ie_type": "Time of First Packet", "ie_value": "Time of First Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Time of Last Packet", "ie_value": "Time of Last Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Usage Information", "ie_value": "Usage Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function reports Usage Reports before and after a Monitoring Time, or before and after QoS enforcement. When present, it shall indicate whether the usage is reported for the period before or after that time, or before or after QoS enforcement."})
ies.append({"ie_type": "Ethernet Traffic Information", "ie_value": "Ethernet Traffic Information", "presence": "C",
            "tlv_more": "0",
            "comment": " This IE shall be present if Ethernet Traffic Information needs to be reported. See Table 7.5.8.3-3."})
group_list["Usage Report Session Deletion Response"] = {"index": "179", "type": "79", "ies": ies}
ies = []
ies.append({"ie_type": "PDR ID", "ie_value": "PDR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the PDR for which downlink data packets have been received at the UP function.More than one IE with this type may be included to represent multiple PDRs having received downlink data packets."})
ies.append(
    {"ie_type": "Downlink Data Service Information", "ie_value": "Downlink Data Service Information", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE shall be included for an PFCP session with an IP PDN type, if the UP function supports the Paging Policy Differentiation feature (see clause 4.9 of 3GPPTS23.401[14]) and clause 5.4.3.2 of 3GPPTS23.501[28]).When present, for each PDR and for each packet that triggers a Downlink Data Notification, the UP function shall copy, into the Paging Policy Indication value within this IE, the value of the DSCP in TOS (IPv4) or TC (IPv6) information received in the IP payload of the GTP-U packet from the PGW (see IETFRFC2474[13]).For 5GC, this IE shall also be included over N4, for each PDR and for each packet that triggers a Downlink Data Notification, if the QFI of the downlink data packet is available.One IE with this type shall be included per PDR ID reported in the message. When multiple PDR ID IEs are present in the message, the Downlink Data Service Information IEs shall be reported according to the order of the PDR ID IEs."})
group_list["Downlink Data Report"] = {"index": "183", "type": "83", "ies": ies}
ies = []
ies.append({"ie_type": "URR ID", "ie_value": "URR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the URR for which usage is reported."})
ies.append({"ie_type": "UR-SEQN", "ie_value": "UR-SEQN", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall uniquely identify the Usage Report for the URR (see clause 5.2.2.3)."})
ies.append({"ie_type": "Usage Report Trigger", "ie_value": "Usage Report Trigger", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the trigger for this report."})
ies.append({"ie_type": "Start Time", "ie_value": "Start Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was started."})
ies.append({"ie_type": "End Time", "ie_value": "End Time", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, except if the Usage Report Trigger indicates Start of Traffic, Stop of Traffic or  MAC Addresses Reporting.When present, this IE shall provide the timestamp when the collection of the information in this report was generated."})
ies.append({"ie_type": "Volume Measurement", "ie_value": "Volume Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a volume measurement needs to be reported."})
ies.append({"ie_type": "Duration Measurement", "ie_value": "Duration Measurement", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if a duration measurement needs to be reported."})
ies.append(
    {"ie_type": "Application Detection Information", "ie_value": "Application Detection Information", "presence": "C",
     "tlv_more": "0", "comment": "This IE shall be present if application detection information needs to be reported."})
ies.append({"ie_type": "UE IP Address", "ie_value": "UE IP address", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the start or stop of an application has been detected and no UE IP address was provisioned in the PDI. See NOTE 1."})
ies.append({"ie_type": "Network Instance", "ie_value": "Network Instance", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the start or stop of an application has been detected, no UE IP address was provisioned in the PDI and multiple PDNs with overlapping IP addresses are used in the UP function. See NOTE 1."})
ies.append({"ie_type": "Time of First Packet", "ie_value": "Time of First Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Time of Last Packet", "ie_value": "Time of Last Packet", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if available for this URR."})
ies.append({"ie_type": "Usage Information", "ie_value": "Usage Information", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function reports Usage Reports before and after a Monitoring Time, or before and after QoS enforcement. When present, it shall indicate whether the usage is reported for the period before or after that time, or before or after QoS enforcement."})
ies.append({"ie_type": "Query URR Reference", "ie_value": "Query URR Reference", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if this usage report is sent as a result of a query URR received in an PFCP Session Modification Request and the Query URR Reference IE was present in the PFCP Session Modification Request.When present, it shall be set to the Query URR Reference value received in the PFCP Session Modification Request. "})
ies.append({"ie_type": "Event Time Stamp", "ie_value": "Event Time Stamp", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present, if the report is related to an event.When present, it shall be set to the time when the event occurs.Several IEs with the same IE type may be present to report multiple occurrences for an event for this URR ID."})
ies.append({"ie_type": "Ethernet Traffic Information", "ie_value": "Ethernet Traffic Information", "presence": "C",
            "tlv_more": "0",
            "comment": " This IE shall be present if Ethernet Traffic Information needs to be reported. See Table 7.5.8.3-3."})
group_list["Usage Report Session Report Request"] = {"index": "180", "type": "80", "ies": ies}
ies = []
ies.append({"ie_type": "Application ID", "ie_value": "Application ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the Application ID for which a start or stop of traffic is reported."})
ies.append(
    {"ie_type": "Application Instance ID", "ie_value": "Application Instance ID", "presence": "C", "tlv_more": "0",
     "comment": "When present, this IE shall identify the Application Instance Identifier for which a start or stop of traffic is reported. It shall be present, when reporting the start of an application, if the Reduced Application Detection Information flag was not set in the Measurement Information and if the flow information for the detected application is deducible. It shall be present, when reporting the stop of an application, if the Reduced Application Detection Information flag was not set in the Measurement Information and if it was provided when reporting the start of the application."})
ies.append({"ie_type": "Flow Information", "ie_value": "Flow Information", "presence": "C", "tlv_more": "0",
            "comment": "When present, this IE shall contain the flow information for the detected application. It shall be present, when reporting the start of an application, if the Reduced Application Detection Information flag was not set in the Measurement Information and if the flow information for the detected application is deducible."})
group_list["Application Detection Information"] = {"index": "168", "type": "68", "ies": ies}
ies = []
ies.append({"ie_type": "MAC Addresses Detected", "ie_value": "MAC Addresses Detected", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if one or more new MAC addresses have been detected.When present, it shall identify the MAC (Ethernet) addresses newly detected as source address of frames sent UL by the UE."})
ies.append({"ie_type": "MAC Addresses Removed", "ie_value": "MAC Addresses Removed", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if one or more new MAC addresses have been removed.When present, it shall identify the MAC (Ethernet) addresses that have been inactive for a duration exceeding the Ethernet inactivity Timer. "})
group_list["Ethernet Traffic Information"] = {"index": "243", "type": "143", "ies": ies}
ies = []
ies.append({"ie_type": "F-TEID", "ie_value": "Remote F-TEID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the remote F-TEID of the GTP-U bearer for which an Error Indication has been received at the UP function.More than one IE with this type may be included to represent multiple remote F-TEID for which an Error Indication has been received."})
group_list["Error Indication Report"] = {"index": "199", "type": "99", "ies": ies}
ies = []
ies.append({"ie_type": "BAR ID", "ie_value": "BAR ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall identify the BAR Rule to be modified."})
ies.append(
    {"ie_type": "Downlink Data Notification Delay", "ie_value": "Downlink Data Notification Delay", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE shall be present if the UP function indicated support of the Downlink Data Notification Delay parameter (see clause 8.2.25) and the Downlink Data Notification Delay needs to be modified.When present, it shall contain the delay the UP function shall apply between receiving a downlink data packet and notifying the CP function about it, when the Apply Action parameter requests to buffer the packets and notify the CP function."})
ies.append({"ie_type": "DL Buffering Duration", "ie_value": "DL Buffering Duration", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the UP function indicated support of the DL Buffering Duration parameter (see clause 8.2.25) and extended buffering of downlink data packet is required in the UP function.When present, this IE shall indicate the duration during which the UP function shall buffer the downlink data packets without sending any further notification to the CP function about the arrival of DL data packets."})
ies.append({"ie_type": "DL Buffering Suggested Packet Count", "ie_value": "DL Buffering Suggested Packet Count",
            "presence": "O", "tlv_more": "0",
            "comment": "This IE may be present if extended buffering of downlink data packet is required in the UP function.When present, this IE shall indicate the maximum number of downlink data packets suggested to be buffered in the UP function."})
ies.append(
    {"ie_type": "Suggested Buffering Packets Count", "ie_value": "Suggested Buffering Packets Count", "presence": "C",
     "tlv_more": "0",
     "comment": "This IE may be present if the UP Function indicated support of the feature UDBC.When present, it shall contain the number of packets that are suggested to be buffered when the Apply Action parameter requests to buffer the packets. The packets that exceed the limit shall be discarded."})
group_list["Update BAR PFCP Session Report Response"] = {"index": "112", "type": "12", "ies": ies}
