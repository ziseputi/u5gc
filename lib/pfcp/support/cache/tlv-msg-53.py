ies = []
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the acceptance or the rejection of the corresponding request message."})
ies.append({"ie_type": "Offending IE", "ie_value": "Offending IE", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the rejection is due to a conditional or mandatory IE missing or faulty."})
ies.append({"ie_type": "Created PDR", "ie_value": "Created PDR", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be present if the cause is set to success, new PDR(s) were requested to be created and the UP function was requested to allocate the local F-TEID for the PDR(s).When present, this IE shall contain the PDR information associated to the PFCP session.See Table 7.5.3.2-1."})
ies.append(
    {"ie_type": "Load Control Information", "ie_value": "Load Control Information", "presence": "O", "tlv_more": "0",
     "comment": "The UP function may include this IE if it supports the load control feature and the feature is activated in the network.See Table 7.5.3.3-1."})
ies.append({"ie_type": "Overload Control Information", "ie_value": "Overload Control Information", "presence": "O",
            "tlv_more": "0",
            "comment": "During an overload condition, the UP function may include this IE if it supports the overload control feature and the feature is activated in the network."})
ies.append({"ie_type": "Usage Report Session Modification Response", "ie_value": "Usage Report", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if:	- the Query URR IE was present or the QAURR flag was set to 1 in the PFCP Session Modification Request,	- traffic usage measurements for that URR are available at the UP function, and	- the UP function decides to return some or all of the requested usage reports in the PFCP Session Modification Response.This IE shall be also present if:	- a URR or the last PDR associated to a URR has been removed,	- non-null traffic usage measurements for that URR are available in the UP function, and	- the UP function decides to return some or all of the related usage reports in the PFCP Session Modification Response (see clause 5.2.2.3.1).Several IEs within the same IE type may be present to represent a list of Usage Reports."})
ies.append({"ie_type": "Failed Rule ID", "ie_value": "Failed Rule ID", "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the Cause IE indicates a rejection due to a rule creation or modification failure."})
ies.append({"ie_type": "Additional Usage Reports Information", "ie_value": "Additional Usage Reports Information",
            "presence": "C", "tlv_more": "0",
            "comment": "This IE shall be included if the Query URR IE was present or the QAURR flag was set to 1 in the PFCP Session Modification Request, and usage reports need to be sent in additional PFCP Session Report Request messages (see clause 5.2.2.3.1).When present, this IE shall either indicate that additional usage reports will follow, or indicate the total number of usage reports that need to be sent in PFCP Session Report Request messages.   "})
ies.append({"ie_type": "Created Traffic Endpoint", "ie_value": "Created/Updated Traffic Endpoint", "presence": "C",
            "tlv_more": "0",
            "comment": "This IE shall be present if the cause is set to success, Traffic Endpoint(s) were requested to be created or updated, and the UP function was requested to allocate the local F-TEID for the Traffic Endpoint(s).When present, this IE shall contain the Traffic Endpoint information associated to the PFCP session.See Table 7.5.3.5-1."})
msg_list[key]["ies"] = ies
