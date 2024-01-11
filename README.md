# System **REV**i**E**w and **A**nalsis too**L** (REVEAL) 

The scripts in the directory collector-scripts can be used to collect system information or information from the Active
Directory. The Flask based application "REVEAL" can be used to import the scripts into a (sqlite/PostgreSQL) database,
analyse the information and to generate reports based on provided templates.

I used those collector scripts already in several assessments collecting information from IT and OT systems. This
includes DCS systems (e.g., PCS7, 800xA, DeltaV), MES systems (e.g., PASX, SIMATIC IT, Opcenter), Historians (e.g.,
IP21), several HMIs as well as systems in laboratories operating measuring devices or HPLCs.

# License 

This TOOL is licensed under the GNU General Public License in version 3. See http://www.gnu.org/licenses/ for further
details.

# Usage

for further information see [WIKI](https://github.com/c-bless/reveal/wiki). Some examples:

## Installation / Usage of REVEAL
* [Building Docker images for REVEAL web application](https://github.com/c-bless/reveal/wiki/Build-Docker-Images-and-setup-REVEAL-web-application). This is the preferred way of using the application 
* [Manual use of REVEAL web application without Docker](https://github.com/c-bless/reveal/wiki/Manual-installation-and-start-of-REVEAL-web-application-without-Docker). This is mainly used during development 
* [Data Collection via PowerShell and Import into REVEAL web application](https://github.com/c-bless/reveal/wiki/Data-Collection-and-importing-results)

## Reports / Word Export

* [Templates for reports](https://github.com/c-bless/reveal/wiki/Templates-for-DOCX-reports)
* [Description of object types usable in reports](https://github.com/c-bless/reveal/wiki/Object-Types-imported-from-Sysinfo%E2%80%90Collector)
