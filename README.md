# vo-VulnDependencyMapper
Analyzes vulnerability reports against a dependency graph of applications (for example derived from SBOMs or runtime analysis) to identify the impact of vulnerabilities on different application components and prioritize patching based on application criticality.

Matching: a report entry lists affected dependencies by name. An entry may optionally carry an affected version range, and when it does, the version in the dependency graph is tested against that range before the component is reported as affected. An entry with no range matches on name only.

Report entry shape: each entry has cve_id, description, cvss_score, and affected_dependencies. Each affected dependency is either a plain name string, or an object with a name field and an optional affected_range field holding a comma separated range such as ">=1.0,<2.0" using >=, <=, >, <, ==, or !=. Ranges come from the operator supplied report input; the tool does not invent them.

## Install
`git clone https://github.com/ShadowGuard-AI/vo-vulndependencymapper`

## Usage
`python main.py --report_file reports.json --dependency_file graph.json [--output results.json]`
`python main.py --cve_id CVE-2023-1234 --enrich`

Analysis requires both input files: --report_file without --dependency_file is an error and exits non-zero.

## Parameters
- `-h`: Show help message and exit
- `--report_file`: Path to the vulnerability report file (JSON format). Requires --dependency_file.
- `--dependency_file`: Path to the dependency graph file (JSON format). Requires --report_file.
- `--cve_id`: CVE ID to query and analyze (for example CVE-2023-1234).
- `--output`: Path to output the results (JSON format). Must not equal an input path.
- `--enrich`: Enrich vulnerability data from the NVD. Used with --cve_id.

## License
Copyright (c) ShadowGuard-AI
