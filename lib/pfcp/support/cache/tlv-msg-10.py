ies = []
ies.append({"ie_type": "Node ID", "ie_value": "Node ID", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall contain the unique identifier of the sending Node."})
ies.append({"ie_type": "Cause", "ie_value": "Cause", "presence": "M", "tlv_more": "0",
            "comment": "This IE shall indicate the acceptance or the rejection of the corresponding request message."})
msg_list[key]["ies"] = ies
