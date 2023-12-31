#  System **REV**i**E**w and **A**nalsis too**L** (REVEAL) #

The scripts in the directory collector-scripts can be used to collect system information or information from the Active Directory. The Flask based applicaton "REVEAL" can be used to import the scripts into a (sqlite/PostgreSQL) database, analyse the information and to generate reports based on provided templates.

I used those collector scripts already in several assessments collecting information from IT and OT systems. This includes DCS systems (e.g., PCS7, 800xA, DeltaV), MES systems (e.g., PASX, SIMATIC IT, Opcenter), Historians (e.g., IP21), several HMIs as well as systems in laboratories operating measuring devices or HPLCs.  

## License ##
This TOOL is licensed under the GNU General Public License in version 3. See http://www.gnu.org/licenses/ for further details.


## Usage with docker ##

The Makefile covers necessary steps for downloading of dependencies, creating Docker Images (with Postgres, Python/Gunicorn and Nginx as Reverse Proxy) and setting up the application.

**Note:**
It is recommended to change db user passwords before building Docker images. Those can be found under:

- service/db/Dockerfile (Variable: POSTGRES_PASSWORD)
- service/web/webapp.env (password in connection string: DATABASE_URL)
- service/api/webapi.env (password in connection string: DATABASE_URL)

**Build and Setup**

1. Download AdminLTE / Bootstrap dependencies and Build Docker Images `make build`. *It is recommended to changes passwords in environment variables before this step.*
2. Run Docker Images `make run`
3. Create first user and import End of Life dates `make init-db`. This needs to be done in a secound console window while images are running. (!!! Initial password for user admin is printed to stdout, make sure you note it ;) !!!)


**Ports reachable on docker containers:**

- 80: Nginx reverse proxy for webapp (http) -> redirect to port 443 (https)
- 443: Nginx reverse proxy for webapp (https)
- 8443: Nginx reverse proxy for webapi (https)

### CLI Commands to interact with dockerized application ###

Needs to be run from root directory of this repository while Docker Images are running.

**User Management:**

- Create user (initial password will be printed to stdout): `docker-compose exec webapp flask -e webapp.env user create <USERNAME>`
- List user accounts (name/UUID): `docker-compose exec webapp flask -e webapp.env user list`
- Reset user password and API-Token: `docker-compose exec webapp flask -e webapp.env user reset <USERNAME>`
- Delete user accounts: `docker-compose exec webapp flask -e webapp.env user delete <USERNAME>`

**Imported data:**

- Clear imported data (hosts, domains, etc.). This will keep login user: `docker-compose exec webapp flask -e webapp.env db clear`
- Import all files within the upload directory of Docker Image: `docker-compose exec webapp flask -e webapp.env import dir /app/uploads`

## Import data via web interface ##
1. Upload results from collector scripts (Menu: "Upload Files")
2. Import uploaded files ("Import Files"). You can choose to import a single uploaded file or all at once. 
3. Analyze imported data.


## Manual installation to run applications locally ##

### Use download-dependencies.sh ###
The base directory of the repository contains an installation file called *download-dependencies.sh*. This file will download current version of 3rd-Party dependencies and copy required static files (e.g., of Admin-LTE) to local directories.  

#### Manually install 3rd party dependencies ###
1. Download Admin-LTE (e.g., https://github.com/ColorlibHQ/AdminLTE/archive/refs/tags/v3.2.0.zip )
2. extract the zip file and copy *dist* and *plugins* folders to directory *reveal/web/static/*

#### Install python dependencies ####
1. clone repository: `git clone https://github.com/c-bless/reveal.git`
2. create virtual environment for webapp and webapi (requirement.txt files can be found under 'services/api' and 'services/web')
```
cd reveal
python -m venv venv
```
3. activate virtual environment `source venv\bin\activate`
4. install requirements (in folder *services/web* or *service/api*): `pip install -r requirements.txt`

#### Import End-Of-Life Dates ####
from cmd in folder 'update-data'
```
flask import eol ../update-data/win-support-dates.csv

```


## Usage ##


### Collect Data (System Information): ###

Use collector script *sysinfo-collector.ps1* located in directory *collector-scripts*. The script has optional parameters *SystemGroup* and *Location* to specify additional information stored with the host. If parameters are not set "N/A" is used for them.

Example (without parameters):
```
.\sysinfo-collector.ps1
```


Example (with parameters):
```
.\sysinfo-collector.ps1 -Systemgroup PCS7 -Location "Production Area"
```

### Collect Data (Active Directory): ###

Information can be collected with one of the collector scripts. *domain-collector_full.ps1* collects most information and could be used for smaller domains. It enumerates group memberships for all groups and selects more properties from computer objects.
*domain-collector_brief.ps1* is selecting less information on computer objects and enumerates only the memberships for the groups "Domain Admins", "Enterprise Admins", "Schema Admins", "DNSAdmins".
*domain-collector-basic.ps1* is work in progress and selects information without Microsofts AD-Module. Currently only a few things are collected.

Example (full group enumeration and more computer properties):
```
.\domain-collector_full.ps1
```

Example (enumeration of a few groups (e.g., domain admins) and less computer properties are collected):
```
.\domain-collector_brief.ps1
```


Example (first draft version, enumeration of a AD infos with AD-Module, less information is collected):
```
.\domain-collector_basic.ps1
```



Example (full group enumeration and more computer properties):
```
.\domain-collector_full.ps1
```


### Import Data (by using Docker images) ###
Files can be uploaded and imported via web interface:
1. Upload Files: *Import Data* -> *Upload Files* -> choose XML files to upload (results from collector scripts)
2. Import Files: *Import Data* -> *Import Files* -> Import Files one by one or all at once.


### Import Data (without Docker) ###

Needs to be run from root directory of this repository and `FLASK_APP=reveal.app:app` must be set


Data can be imported via `flask import file <file>` or  `flask import dir <dir>`. The *import file* command can be used to import data collected via *sysinfo-collector.ps1* or *domain-collector* scripts. The *import file* command can import multiple outputs within a directory.

Example (import result from *sysinfo-collector.ps1*):
```
flask import file /path/to/SysInfo-Collector.xml
```

Example (import result from *domain-collector* scripts):
```
flask import file /path/to/Domain-Collector.xml
```

Example (import directory with results from collector scripts):
```
flask import dir /path/to/result/folder/
```


### Start application (after import) ####

Before Running the Webapplication or API you need to set the FLASK_APP environment variable to the corresponding app.
- For Webapp: `FLASK_APP=reveal.app:app`
- For Webapi: `FLASK_APP=reveal.api:app`

```
flask run
```
or in debug mode

```
flask --debug run
```

if you want to run both applications you need to specify a different port for one application:

```
flask run --port 8001
```
or in debug mode

```
flask --debug run --port 8001
```
### Overview of CLI commands ###

**User Management:**

- Create user (initial password will be printed to stdout): `flask user create <USERNAME>`
- List user accounts (name/UUID): `flask user list`
- Reset user password and API-Token: `flask user reset <USERNAME>`
- Delete user accounts: `flask user delete <USERNAME>`

**Imported data:**

- Clear imported data (hosts, domains, etc.). This will keep login user: `flask db clear`
- Import all files within a given directory: `flask import dir <DIR>`
- Import result from collector script: `flask import file <DIR>`
- Import all files within a given directory: `flask import dir <DIR>`
