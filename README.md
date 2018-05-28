# Finding Security Issues in (Open Source) Software Repositories 

* **ID:** 2018-tuos-adb-ug-10a
* **Student:** Zer J Eng <zjeng1@sheffield.ac.uk>
* **Cohorts:** CS/Math/SE (other after approval by supervisor) 
* **Keywords:** source code control, software security, vulnerability,
                CVSS, CWE, patch analysis, source code analysis, Open
                Source, FOSS, repository mining, github

## Description 

Not all Free/Libre and Open Source (FLOSS) Projects publish fixed
software vulnerabilities in an easy to consume manner (e.g., as
CVEs). Moreover, even if they do, it is often not easy to identify the
actual code commit fixing a security vulnerability.

As for users of FLOSS components, it is important to understand which
vulnerabilities are known and when/how they were fixed, it is
important to have an in-depth understanding of vulnerabilities in FLOSS
components (of course, also for an attacker/hacker, this information
is of value). 

In this project, a repository mining tool should be developed that
is, e.g., able to detect 

* silent patches/fixed, i.e., commits that fix security
  vulnerabilities that are not yet known 
* commits that fix known vulnerabilities 

The project can be extended to learn/derive from the identified
commits configuration for security testing tools that help to decide
if an application using the component is affected by the vulnerability
or not.

## Skills required:

 * Good programming skills 
 * Good understating of source code control systems (e.g. git)
 * An interest in application security 

## Initial reading and useful links:

 * OWASP Top 10: <https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project>
 * <https://github.com/TQRG/secbench-mining-tool>
