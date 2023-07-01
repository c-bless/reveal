# README #

The scripts in the directory collector-scripts can be used to collect system information or information from the Active Directory. The Flask based applicaton "systemdb" can be used to import the scripts into a sqlite database, analyse the information and to generate reports based on provided templates.

## License ##
This TOOL is licensed under the GNU General Public License in version 3. See http://www.gnu.org/licenses/ for further details.


## Usage ##

### Installation: ###
1. clone repository: `git clone https://bitbucket.org/cbless/systemdb.git`
2. create virtual environment
```
cd systemdb
python -m venv venv
```
3. activate virtual environment `source venv\bin\activate`
4. install requirements (in folder *systemdb*): `pip install -r requirements.txt`

### Import End-Of-Life Dates ###
from cmd in folder systemdb
```
flask import eol ../update-data/win-support-dates-2023-06.csv

```

### Collect Data (System Information): ###

Use collector script *sysinfo-collector.ps1* located in directory *collector-scripts*. The script has optional parameters *SystemGroup* and *Location* to specify additional information stored with the host. If parameters are not set "N/A" is used for them.

Example (without parameters):
```
.\sysinfo-colloctor.ps1
```


Example (with parameters):
```
.\sysinfo-colloctor.ps1 -Systemgroup PCS7 -Location "Production Area"
```

### Collect Data (Active Directory): ###

Information can be collected with one of the collector scripts. *domain-collector_full.ps1* collects most information and could be used for smaller domains. It enumerates group memberships for all groups and selects more properties from computer objects.
*domain-collector_brief.ps1* is selecting less information on computer objects and enumerates only the memberships for the groups "Domain Admins", "Enterprise Admins", "Schema Admins", "DNSAdmins".
*domain-collector-basic.ps1* is work in progress and selects information without Microsofts AD-Module. Currently only a few things are collected. 

Example (full group enumeration and more computer properties):
```
.\sysinfo-colloctor_full.ps1
```

Example (enumeration of a few groups (e.g., domain admins) and less computer properties are collected):
```
.\sysinfo-colloctor_brief.ps1
```


Example (first draft version, enumeration of a AD infos with AD-Module, less information is collected):
```
.\sysinfo-colloctor_basic.ps1
```



Example (full group enumeration and more computer properties):
```
.\sysinfo-colloctor_full.ps1
```

### Import Data ###

Data can be imported via `flask import <type> <file>`. Type could be either **host** (collected via *sysinfo-collector.ps1*), **domain** (collected via *domain-collector* scripts) or **dir** to specify a directory containing results from collector scripts (both types).

Example (import result from *sysinfo-collector.ps1*):
```
flask import host /path/to/SysInfo-Collector.xml
```

Example (import result from *domain-collector* scripts):
```
flask import domain /path/to/Domain-Collector.xml
```

Example (import directory with results from collector scripts):
```
flask import dir /path/to/result/folder/
```

### Start application (after import) ####

```
flask run
```
or in debug mode

```
flask --debug run
```
