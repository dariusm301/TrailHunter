import xml.etree.ElementTree as ET

def _extract_task_details(xml_string: str) -> dict:
    details = {
        "command": None,
        "arguments": None,
        "com_class": None
    }
    
    if not xml_string:
        return details

    try:
        ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        root = ET.fromstring(xml_string)

        exec_node = root.find(".//t:Exec", ns)
        if exec_node is not None:
            cmd = exec_node.find("t:Command", ns)
            args = exec_node.find("t:Arguments", ns)
            details["command"] = cmd.text if cmd is not None else None
            details["arguments"] = args.text if args is not None else None

        com_node = root.find(".//t:ComHandler", ns)
        if com_node is not None:
            class_id = com_node.find("t:ClassId", ns)
            details["com_class"] = class_id.text if class_id is not None else None

        principal = root.find(".//t:Principal/t:UserId", ns)
        if principal is not None:
            details["userid"] = principal.text

    except Exception as e:
        pass
        
    return details