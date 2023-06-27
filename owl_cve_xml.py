import os
import json
import xml.etree.ElementTree as ET

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

filename = "Paper_ontology.owl"

# ElementTree root
tree:ET.ElementTree = None
root:ET.Element = None
xml_ns:str = None

# Changes to make to file
new_cves = []
device_cve_dict = {}

# TO DO: check for existing CVEs in original owl
existing_cves: list[str] = []


###################################################
# Functions to add new xml elements to owl file
###################################################

def AddCveHasSubRelation(device: str, cve_name: str):
    subclass_of = ET.Element("SubClassOf")

    subclass = ET.Element("Class") 
    subclass.attrib["IRI"] = f"#{device}"
    subclass_of.append(subclass)

    objallval = ET.Element("ObjectSomeValuesFrom")
    objprop = ET.Element("ObjectProperty")
    objprop.attrib["IRI"] = "#Has"
    objallval.append(objprop)
    cve = ET.Element("Class")
    cve.attrib["IRI"] = f"#{cve_name}"
    objallval.append(cve)
    subclass_of.append(objallval)

    global root
    root.append(subclass_of)


def AddCve(cve_name: str, cve_desc:str, cve_severity: int = None, superclass_name: str = "Vulnerability_and_Exposures"):
    # Create declaration
    decl_element = ET.Element("Declaration")
    cve_class = ET.Element("Class")
    cve_class.attrib["IRI"] = f"#{cve_name}"
    decl_element.append(cve_class)
    
    # Create new subclassof
    subof_element = ET.Element("SubClassOf")
    subclass = ET.Element("Class") 
    subclass.attrib["IRI"] = f"#{cve_name}"
    superclass = ET.Element("Class")
    superclass.attrib["IRI"] = f"#{superclass_name}"
    subof_element.append(subclass)
    subof_element.append(superclass)

    # Create desc comment
    desc_element = ET.Element("AnnotationAssertion")
    anno = ET.Element("AnnotationProperty")
    anno.attrib["abbreviatedIRI"] = "rdfs:comment"
    iri = ET.Element("IRI")
    iri.text = f"#{cve_name}"
    literal = ET.Element("Literal")
    literal.text = f"Desc: {cve_desc}"
    desc_element.append(anno)
    desc_element.append(iri)
    desc_element.append(literal)

    # Create severity comment
    severity_element = ET.Element("AnnotationAssertion")
    anno = ET.Element("AnnotationProperty")
    anno.attrib["abbreviatedIRI"] = "rdfs:comment"
    iri = ET.Element("IRI")
    iri.text = f"#{cve_name}"
    literal = ET.Element("Literal")
    literal.text = f"Severity: {str(cve_severity)}"
    severity_element.append(anno)
    severity_element.append(iri)
    severity_element.append(literal)

    # Add all
    global root
    root.append(decl_element)
    root.append(subof_element)
    root.append(desc_element)
    root.append(severity_element)

    global existing_cves
    existing_cves.append(cve_name)


def AddCvesToOwl():
    global new_cves
    global device_cve_dict

    # output files for debugging
    new_cve_file = open("DEBUG_new_cves.json", "w+")
    json.dump(new_cves, new_cve_file)
    device_cve_dict_file = open("DEBUG_device_cve_dict.json", "w+")
    json.dump(device_cve_dict, device_cve_dict_file)

    comment_element = ET.Comment("Added by script")
    root.append(comment_element)

    for cve in new_cves:
        AddCve(cve["id"], cve["desc"], cve["score"])

    for device,cves in device_cve_dict.items():
        for cve in cves:
            AddCveHasSubRelation(device, cve)


###################################################
# Functions to search CVE json files for devices
###################################################

def CheckDescForDevice(desc:str, device:str) -> bool:
    tokens = desc.lower() \
                .translate({ord(c): " " for c in "()[]"}) \
                .split()
    # print(tokens)
    
    if device.lower() in tokens:
        return True

    if "_" in device:
        device_edit = device.replace("_", " ")
        if device_edit.lower() in desc.lower():
            return True
        
    return False


def SearchCveFile(filepath: str, device_list:list[str]):
    logger.debug(f"Checking {filepath}")

    global new_cves
    global device_cve_dict
    file = open(filepath)
    data = json.load(file)

    cve_added_to_list = False
    try:
        for desc in data["containers"]["cna"]["descriptions"]:
            if desc["lang"] != "en":
                continue

            desc_text = desc["value"]
            for device in device_list:
                if not CheckDescForDevice(desc_text, device):
                    continue

                cve_id = data["cveMetadata"]["cveId"]
                if not cve_added_to_list:
                    cve_dict = {}
                    cve_dict["id"] = cve_id
                    cve_dict["desc"] = desc_text
                    try:
                        cve_score_text = ""
                        for metric in data["containers"]["cna"]["metrics"]:
                            for type, scoring in metric.items():
                                if not isinstance(scoring, dict):
                                    continue
                                score = str(scoring["baseScore"])
                                cve_score_text += f"[{type}: {score}]"
                                
                        if len(cve_score_text) != 0:
                            cve_dict["score"] = cve_score_text
                            logger.debug(f"{cve_id} score found! {cve_score_text}")
                        else:
                            cve_dict["score"] = "None"
                            logger.warning(f"{cve_id} has no score, putting None")
                    except KeyError as e:
                        logger.warning(f"{cve_id} has no score, putting None (key {e} not found)")
                        cve_dict["score"] = "None"

                    new_cves.append(cve_dict)
                    cve_added_to_list = True
                logger.debug(f"Adding {cve_id} for {device}")
                
                if device not in device_cve_dict:
                    device_cve_dict[device] = []
                
                device_cve_dict[device].append(cve_id)
    except KeyError as e:
        logger.warning(f"Error searching CVE json, does not contain key {e}")


def SearchCveDirForDevices(device_list:list[str]):
    for root_dir, dirs, files in os.walk("./cvelistV5/cves"):
        for name in files:
            if name.startswith("CVE") and name.endswith((".json")):
                full_path = os.path.join(root_dir, name)
                SearchCveFile(full_path, device_list)
        

###################################################
# Functions to parse owl file to extract devices
###################################################

def GetDevicesToCheck() -> list[str]:
    # TO DO: properly form class subclass tree
    superclass_list = ["#Communiction_Device",
                        "#Control_Computer",
                        "#ICS_Device",
                        "#Physical_Device",
                        "#BYOD_Device",
                        "#IoT_Device"]

    device_list = []
    class_count = 0
    subclass_rel_list = root.findall(f"{xml_ns}SubClassOf")
    for subclass_of_rel in subclass_rel_list:
        class_list = subclass_of_rel.findall(f"{xml_ns}Class")
        if len(class_list) != 2:
            continue

        try:
            subclass = class_list[0]
            subclass_iri = subclass.attrib["IRI"]
            superclass = class_list[1]
            superclass_iri = superclass.attrib["IRI"]
        except IndexError as e:
            logger.error("<SubClassOf> element does not have 2 <Class>, but passed the list len check")
        except KeyError as e:
            logger.error("<Class> has no IRI attribute")

        # logger.debug(f"<SubClassOf> <Class IRI=\"{subclass_iri}\"> is a subclass of <Class IRI=\"{superclass_iri}\">")
        if superclass_iri not in superclass_list:
            continue

        logger.debug(f"Found {subclass_iri[1:]}")
        device_list.append(subclass_iri[1:])
        class_count += 1

        # else:
        #     logger.debug("<SubClassOf> element does not have 2 <Class>")

    print(class_count)

    return device_list
    

###################################################
# Main and utils
###################################################

# https://stackoverflow.com/questions/54439309/how-to-preserve-namespaces-when-parsing-xml-via-elementtree-in-python
def register_all_namespaces(filename):
    namespaces = dict([node for _, node in ET.iterparse(filename, events=['start-ns'])])
    for ns in namespaces:
        ET.register_namespace(ns, namespaces[ns])


def SetupRoot():
    global filename
    global tree
    try:
        register_all_namespaces(filename)
        tree = ET.parse(filename)
    except ET.ParseError as e:
        print("ERROR : XML Parsing Error in \"" + filename + "\"")

    logger.info(f"XML Parse {filename} - Success")

    global root
    root = tree.getroot()
    global xml_ns
    xml_ns = root.tag[:root.tag.find("}") + 1]
    logger.debug(f"XML Namespace: {xml_ns}")


def WriteNewOwl():
    ET.indent(tree, '    ')
    output_filename = f"SCRIPT_{filename}"
    tree.write(output_filename)

    logger.info(f"Output @ \'{output_filename}\'")


def Main():
    SetupRoot()

    # Find classes to check
    device_list = GetDevicesToCheck()

    # Check cve json files
    SearchCveDirForDevices(device_list)

    # Modify owl file
    AddCvesToOwl()

    # Finalize
    WriteNewOwl()



def Test():
    SetupRoot()

    global new_cves
    global device_cve_dict

    new_cves.append({"id": "CVE-1234-1234",
                    "desc": "TEST DESC 1234",
                    "score": "None",
                    })
    new_cves.append({"id": "CVE-9876-9876",
                    "desc": "TEST DESC 9876",
                    "score": "[cvssV3_1: 2.5]",
                    })

    device_cve_dict["Laptop"] = ["CVE-1234-1234"]
    device_cve_dict["VPN_Server"] = ["CVE-1234-1234",
                                     "CVE-9876-9876"]

    AddCvesToOwl()
    WriteNewOwl()


if __name__ == "__main__":
    Main()
    # Test()