ies = []
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier of the sending Node."})
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the acceptance or the rejection of the corresponding request message."})
ies.append({"ie_type": "Offending IE", "ie_value": "Offending IE", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the rejection is due to a conditional or mandatory IE missing or faulty."})
ies.append({"ie_type": "F-SEID", "ie_value": "UP F-SEID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the cause is set to Request accepted (success). When present, it shall contain the unique identifier allocated by the UP function identifing the session."})
ies.append({"ie_type": "Created PDR", "ie_value": "Created PDR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the cause is set to success and the UP function was requested to allocate a local F-TEID or a UE IP address/prefix for the PDR.When present, this IE shall contain the PDR information associated to the PFCP session. There may be several instances of this IE.See table 7.5.3.2-1."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "Load Control Information", "presence": "O", "tlv_more": "0",
     "comment": "The UP function may include this IE if it supports the load control feature and the feature is activated in the network.See Table 7.5.3.3-1."})
ies.append({"ie_type": "Overload Control Information", "ie_value": "Overload Control Information", "presence": "O",
            "tlv_more": "0",
            "comment": "During an overload condition, the UP function may include this IE if it supports the overload control feature and the feature is activated in the network.See Table 7.5.3.4-1."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "SGW-U FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "FQ-CSID", "ie_value": "PGW-U FQ-CSID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included according to the requirements in clause 23 of 3GPPTS23.007[24]."})
ies.append({"ie_type": "Failed Rule ID", "ie_value": "Failed Rule ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the Cause IE indicates a rejection due to a rule creation or modification failure. "})
ies.append(
    {"ie_type": "Created Traffic Endpoint", "ie_value": "Created Traffic Endpoint", "presence": "C", "tlv_more": "0",
     "comment": "This IE shall be present if the cause is set to success and the UP function was requested to allocate a local F-TEID or a UE IP address/prefix in a Create Traffic Endpoint IE. When present, it shall contain the local F-TEID or UE IP address/prefix to be used for this Traffic Endpoint.There may be several instances of this IE."})
msg_list[key]["ies"] = ies
