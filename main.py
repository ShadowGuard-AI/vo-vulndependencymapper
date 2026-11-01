import argparse
import logging
import json
import os
import sys
import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityReport:
    """
    Represents a vulnerability report, potentially from a CVE database or custom feed.
    """
    def __init__(self, cve_id, description, cvss_score, affected_dependencies):
        """
        Initializes a VulnerabilityReport object.

        Args:
            cve_id (str): The CVE ID of the vulnerability.
            description (str): A description of the vulnerability.
            cvss_score (float): The CVSS score of the vulnerability.
            affected_dependencies (list): A list of dependency names affected by the vulnerability.
        """
        self.cve_id = cve_id
        self.description = description
        self.cvss_score = cvss_score
        self.affected_dependencies = affected_dependencies

    def __str__(self):
        return f"CVE ID: {self.cve_id}, Score: {self.cvss_score}, Dependencies: {self.affected_dependencies}"

class DependencyGraph:
    """
    Represents the dependency graph of an application.  Could be built from SBOM or runtime analysis.
    """
    def __init__(self, application_name, dependencies):
        """
        Initializes a DependencyGraph object.

        Args:
            application_name (str): The name of the application.
            dependencies (dict): A dictionary representing the application's dependencies.
                                   Example: {"dependency_name": {"version": "1.2.3", "criticality": "high"}}
        """
        self.application_name = application_name
        self.dependencies = dependencies

    def __str__(self):
        return f"Application: {self.application_name}, Dependencies: {self.dependencies}"


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="vo-VulnDependencyMapper: Analyzes vulnerability reports against a dependency graph to prioritize patching.")
    parser.add_argument("--report_file", help="Path to the vulnerability report file (JSON format).", required=False)
    parser.add_argument("--dependency_file", help="Path to the dependency graph file (JSON format).", required=False)
    parser.add_argument("--cve_id", help="CVE ID to query and analyze (e.g., CVE-2023-1234).", required=False)
    parser.add_argument("--output", help="Path to output the results (JSON format).", required=False)
    parser.add_argument("--enrich", action="store_true", help="Enrich vulnerability data from external sources (e.g., NVD).", required=False)

    return parser


def load_vulnerability_reports(report_file):
    """
    Loads vulnerability reports from a JSON file.

    Args:
        report_file (str): Path to the vulnerability report file.

    Returns:
        list: A list of VulnerabilityReport objects.  Returns an empty list if the file doesn't exist or is invalid.
    """
    try:
        with open(report_file, 'r') as f:
            reports_data = json.load(f)
            reports = []
            for report_data in reports_data:
                try:
                    # Every field comes from a get with no default beyond None, and building this object cannot really fail, so the error log below almost never fires. A report entry missing its score or its dependency list loads happily and only breaks, or quietly matches nothing, further down.
                    report = VulnerabilityReport(
                        report_data.get('cve_id'),
                        report_data.get('description'),
                        report_data.get('cvss_score'),
                        report_data.get('affected_dependencies')
                    )
                    reports.append(report)
                except Exception as e:
                    logging.error(f"Error creating VulnerabilityReport from data: {report_data}. Error: {e}")
            return reports
    except FileNotFoundError:
        logging.error(f"Vulnerability report file not found: {report_file}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in vulnerability report file: {report_file}")
        return []
    except Exception as e:
        logging.error(f"Error loading vulnerability reports from {report_file}: {e}")
        return []


def load_dependency_graph(dependency_file):
    """
    Loads the dependency graph from a JSON file.

    Args:
        dependency_file (str): Path to the dependency graph file.

    Returns:
        DependencyGraph: A DependencyGraph object. Returns None if the file doesn't exist or is invalid.
    """
    try:
        with open(dependency_file, 'r') as f:
            graph_data = json.load(f)
            dependencies = graph_data.get('dependencies', {}) # Handle missing dependencies
            return DependencyGraph(graph_data.get('application_name'), dependencies)
    except FileNotFoundError:
        logging.error(f"Dependency graph file not found: {dependency_file}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in dependency graph file: {dependency_file}")
        return None
    except Exception as e:
        logging.error(f"Error loading dependency graph from {dependency_file}: {e}")
        return None


def analyze_vulnerabilities(vulnerability_reports, dependency_graph):
    """
    Analyzes the vulnerability reports against the dependency graph.

    Args:
        vulnerability_reports (list): A list of VulnerabilityReport objects.
        dependency_graph (DependencyGraph): A DependencyGraph object.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    if not vulnerability_reports:
        logging.warning("No vulnerability reports provided. Analysis will be empty.")
        return {}

    if not dependency_graph:
        logging.warning("No dependency graph provided. Analysis will be empty.")
        return {}


    analysis_results = {}
    for report in vulnerability_reports:
        vulnerable_components = []
        for dependency in report.affected_dependencies:
            # Matching is by name alone. I never compare the version in my graph against any version range, because the reports carry no range field, so a dependency that was patched long ago still lands in the result as long as its name appears in a report. A reader has to do the version judgement by eye from the output.
            if dependency in dependency_graph.dependencies:
                vulnerable_components.append({
                    "dependency_name": dependency,
                    "version": dependency_graph.dependencies[dependency].get("version", "unknown"),
                    "criticality": dependency_graph.dependencies[dependency].get("criticality", "low")
                })

        if vulnerable_components:
            # Two reports carrying the same CVE id overwrite each other here, last one wins. A feed that splits one CVE across several entries loses all but the final entry, with no count of what was dropped.
            analysis_results[report.cve_id] = {
                "description": report.description,
                "cvss_score": report.cvss_score,
                "affected_components": vulnerable_components
            }

    return analysis_results


def enrich_vulnerability_data(cve_id):
    """
    Enriches vulnerability data from an external source (e.g., NVD).

    Args:
        cve_id (str): The CVE ID to enrich.

    Returns:
        dict: A dictionary containing enriched vulnerability data. Returns None on error.
    """
    try:
        # Example: Fetch data from NVD API (replace with actual API endpoint)
        nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"  # Requires API Key - rate limits.  Consider alternatives, like manually maintained DB.
        response = requests.get(nvd_api_url, timeout=10)  # Add timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        # Extract relevant information (adjust based on API response structure)
        if data and data.get("resultsPerPage") > 0 and data["vulnerabilities"]: # Safe access and check result size
             vulnerability = data["vulnerabilities"][0]["cve"]
             # I take the first description whatever language it is in. NVD usually puts English first, but nothing here checks the lang field, so an enriched result can come back in another language with no sign of why.
             description = vulnerability["descriptions"][0]["value"]
             # Only the 3.1 metrics are read, and only the first entry. A CVE scored only under 4.0 or 3.0 enriches to a severity of None, which prints as a null in the output rather than as a gap the caller is told about.
             cvss_v3_severity = vulnerability.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity")

             enriched_data = {
                 "description": description,
                 "cvss_v3_severity": cvss_v3_severity,
             }
             return enriched_data
        else:
            logging.warning(f"CVE {cve_id} not found in NVD API.")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from NVD API for {cve_id}: {e}")
        return None
    except (KeyError, IndexError) as e:
        logging.error(f"Error parsing NVD API response for {cve_id}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response from NVD API for {cve_id}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error enriching CVE {cve_id}: {e}")
        return None


def output_results(results, output_file):
    """
    Outputs the analysis results to a JSON file.

    Args:
        results (dict): The analysis results.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Analysis results written to: {output_file}")
    except Exception as e:
        logging.error(f"Error writing results to file: {output_file}. Error: {e}")


def main():
    """
    Main function of the vo-VulnDependencyMapper tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation: Check if at least one of report_file or cve_id is provided
    if not (args.report_file or args.cve_id):
        parser.error("Either --report_file or --cve_id must be provided.")

    # Example usage: Analyze vulnerabilities from a report file and a dependency file
    # The branch shape leaves a hole: a report file with no dependency file matches neither branch when no CVE id is given, and the program ends quietly with exit 0 and no output at all. Nothing tells the caller a second file was needed.
    if args.report_file and args.dependency_file:
        vulnerability_reports = load_vulnerability_reports(args.report_file)
        dependency_graph = load_dependency_graph(args.dependency_file)
        # An empty report list and a failed load look identical at this point, because the loader returns an empty list for a missing file too. The run then prints nothing and exits 0, so a mistyped path reads exactly like a scan that found no overlap.
        if vulnerability_reports and dependency_graph:
            analysis_results = analyze_vulnerabilities(vulnerability_reports, dependency_graph)
            if args.output:
                output_results(analysis_results, args.output)
            else:
                print(json.dumps(analysis_results, indent=4))

    # Example usage: Enrich vulnerability data for a single CVE ID
    elif args.cve_id:
        if args.enrich:
            enriched_data = enrich_vulnerability_data(args.cve_id)
            if enriched_data:
                print(json.dumps(enriched_data, indent=4))
            else:
                logging.warning(f"Failed to enrich data for CVE: {args.cve_id}")
        else:
            print(f"CVE ID: {args.cve_id}.  Use --enrich to retrieve more info.")


if __name__ == "__main__":
    main()
