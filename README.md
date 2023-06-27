# Ontology_CVE_Populator

## How to get:
1. <code>git clone https://github.com/smartgridadsc/Ontology_CVE_Populator.git</code>
2. <code>git submodule init</code>
3. <code>git submodule update</code>
4. Install python modules as necessary.

## How to use:
### Populating the ontology
- Copy your ontology file into this directory.
- Edit <code>owl_cve_xml.py</code> and change the filename</code> to your ontology file's name.
- <code>python3 owl_cve_xml.py</code> - Used to populate the .owl ontology with CVEs from the downloaded database from <code>CVEProject/cvelistV5</code>. This command generates 3 files:
  1. <code>SCRIPT_ontology_filename.owl</code> - The new .owl file populated with CVEs
  2. <code>DEBUG_new_cves.json</code> - Used for debugging. Contains a list of new CVEs to add to the .owl file.
  3. <code>DEBUG_devices_cve_dict.json</code> - Used for debugging. Contains a dictionary of devices to their related CVEs.
### Debugging
Both of these commands require the <code>DEBUG_*.json</code> files listed above to run:
- <code>python3 TestParseCVE.py</code> - Contains some functions to test the CVE parsing functions. Edit it to customise the tests.
- <code>python3 Debug.py</code> - A script to print out some results of the CVE parsing.
