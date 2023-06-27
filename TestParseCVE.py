import owl_cve_xml as CVE

def SearchDeviceAllCves(device:str):
    devicelist = [device]
    
    CVE.SearchCveDirForDevices(devicelist)

    print(CVE.device_cve_dict[device])
    print(len(CVE.device_cve_dict[device]))

    # cleanup
    CVE.device_cve_dict = {}
    CVE.new_cves = []

def SearchDeviceOneCve(device:str, cve_path:str):
    devicelist = [device]
    
    CVE.SearchCveFile(cve_path, devicelist)

    print(CVE.device_cve_dict[device])
    print(len(CVE.device_cve_dict[device]))

    # cleanup
    CVE.device_cve_dict = {}
    CVE.new_cves = []

if __name__ == "__main__":
    device = "IED"
    
    # SearchDeviceAllCves(device)
    SearchDeviceOneCve(device, "./cvelistV5/cves/2022/2xxx/CVE-2022-2513.json")


