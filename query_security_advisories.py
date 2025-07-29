import requests
from typing import List, Dict, Optional
from packaging import version as pkg_version
from config import GITHUB_TOKEN


def is_version_affected(version: str, vulnerable_range: str) -> bool:
    """
    Check if a version is within a vulnerable range.
    
    Args:
        version: The version to check (e.g., "2.0.1")
        vulnerable_range: The vulnerable range (e.g., "< 2.1.0", ">= 1.0.0, < 2.0.0")
    
    Returns:
        True if the version is affected, False otherwise
    """
    try:
        # Parse the version
        ver = pkg_version.parse(version)
        
        # Handle range cases (e.g., ">= 1.0.0, < 2.0.0")
        if ", " in vulnerable_range:
            parts = vulnerable_range.split(", ")
            # For ranges, ALL conditions must be true
            for part in parts:
                part = part.strip()
                if part.startswith("< "):
                    max_ver = pkg_version.parse(part[2:])
                    if not (ver < max_ver):
                        return False
                elif part.startswith("<= "):
                    max_ver = pkg_version.parse(part[3:])
                    if not (ver <= max_ver):
                        return False
                elif part.startswith("> "):
                    min_ver = pkg_version.parse(part[2:])
                    if not (ver > min_ver):
                        return False
                elif part.startswith(">= "):
                    min_ver = pkg_version.parse(part[3:])
                    if not (ver >= min_ver):
                        return False
                elif part.startswith("= "):
                    exact_ver = pkg_version.parse(part[2:])
                    if not (ver == exact_ver):
                        return False
            return True
        
        # Handle simple cases
        if vulnerable_range.startswith("< "):
            max_ver = pkg_version.parse(vulnerable_range[2:])
            return ver < max_ver
        elif vulnerable_range.startswith("<= "):
            max_ver = pkg_version.parse(vulnerable_range[3:])
            return ver <= max_ver
        elif vulnerable_range.startswith("> "):
            min_ver = pkg_version.parse(vulnerable_range[2:])
            return ver > min_ver
        elif vulnerable_range.startswith(">= "):
            min_ver = pkg_version.parse(vulnerable_range[3:])
            return ver >= min_ver
        elif vulnerable_range.startswith("= "):
            exact_ver = pkg_version.parse(vulnerable_range[2:])
            return ver == exact_ver
        
        # If we can't parse it, don't assume affected
        return False
        
    except Exception as e:
        # If parsing fails, print for debugging but don't assume affected
        print(f"Warning: Could not parse version range '{vulnerable_range}': {e}")
        return False


def query_security_advisories(package_name: str, version: Optional[str] = None, ecosystem: str = "PIP") -> List[Dict]:
    """
    Query GitHub Security Advisories GraphQL API for vulnerabilities in a package.
    
    Args:
        package_name: Name of the package to check
        version: Package version to check (optional)
        ecosystem: Package ecosystem (PIP for Python, NPM for JavaScript, MAVEN for Java, etc.)
    
    Returns:
        List of security advisories for the package
    """
    
    # GitHub GraphQL API endpoint
    url = "https://api.github.com/graphql"
    
    # GraphQL query to search for security advisories
    query = """
    query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
      securityVulnerabilities(
        first: 100
        package: $package
        ecosystem: $ecosystem
      ) {
        nodes {
          advisory {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            references {
              url
            }
            cvss {
              score
              vectorString
            }
          }
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
    """
    
    # Variables for the GraphQL query
    variables = {
        "package": package_name,
        "ecosystem": ecosystem
    }
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json={"query": query, "variables": variables}, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        if "errors" in data:
            print(f"GraphQL errors: {data['errors']}")
            return []
        
        vulnerabilities = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
        
        # Format the results
        advisories = []
        for vuln in vulnerabilities:
            if vuln and vuln.get("advisory"):
                advisory = vuln["advisory"]
                vulnerable_range = vuln.get("vulnerableVersionRange", "")
                
                # If version is provided, check if it's affected
                if version and version != "Unknown":
                    # Simple check - in production, you'd want proper version comparison
                    # This checks if the version appears to be in the vulnerable range
                    if not is_version_affected(version, vulnerable_range):
                        continue
                
                advisories.append({
                    "ghsa_id": advisory.get("ghsaId", ""),
                    "summary": advisory.get("summary", ""),
                    "description": advisory.get("description", ""),
                    "severity": advisory.get("severity", ""),
                    "published_at": advisory.get("publishedAt", ""),
                    "updated_at": advisory.get("updatedAt", ""),
                    "vulnerable_range": vulnerable_range,
                    "first_patched_version": vuln.get("firstPatchedVersion", {}).get("identifier", "") if vuln.get("firstPatchedVersion") else "",
                    "cvss_score": advisory.get("cvss", {}).get("score", 0) if advisory.get("cvss") else 0,
                    "cvss_vector": advisory.get("cvss", {}).get("vectorString", "") if advisory.get("cvss") else "",
                    "references": [ref["url"] for ref in advisory.get("references", [])]
                })
        
        return advisories
        
    except requests.exceptions.RequestException as e:
        print(f"Error querying GitHub API: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []


def detect_ecosystem(module_name: str) -> str:
    """
    Try to detect the ecosystem based on module name patterns.
    This is a simple heuristic approach.
    """
    # Common Python packages
    python_indicators = ["django", "flask", "numpy", "pandas", "requests", "scipy", "matplotlib", 
                        "pytest", "sqlalchemy", "celery", "pillow", "beautifulsoup"]
    
    # Common Java packages
    java_indicators = ["org.springframework", "com.google", "org.apache", "javax", "java.", 
                      "org.junit", "org.hibernate"]
    
    # Common JavaScript packages
    js_indicators = ["react", "vue", "angular", "express", "lodash", "axios", "webpack", 
                    "babel", "eslint", "jest"]
    
    module_lower = module_name.lower()
    
    # Check for Java-style package names
    if "." in module_name and (module_name.startswith("org.") or module_name.startswith("com.") or 
                               module_name.startswith("javax.") or module_name.startswith("java.")):
        return "MAVEN"
    
    # Check against known patterns
    for indicator in python_indicators:
        if indicator in module_lower:
            return "PIP"
    
    for indicator in js_indicators:
        if indicator in module_lower:
            return "NPM"
    
    # Default to PIP for this Flask project
    return "PIP"


if __name__ == "__main__":
    # Test with a few known packages with versions
    test_packages = [
        ("flask", "2.3.2"),
        ("flask", "0.12.0"),  # Old version with known vulnerabilities
        ("requests", "2.31.0"),
        ("django", "4.2.0")
    ]
    
    if not GITHUB_TOKEN:
        print("Warning: No GitHub token found. API rate limits will be very restrictive.")
        print("Set GITHUB_PAT environment variable for better results.\n")
    
    for package, version in test_packages:
        print(f"\nChecking security advisories for: {package} version {version}")
        print("-" * 60)
        
        ecosystem = detect_ecosystem(package)
        advisories = query_security_advisories(package, version, ecosystem)
        
        if advisories:
            print(f"Found {len(advisories)} security advisories affecting version {version}:")
            for adv in advisories[:3]:  # Show first 3
                print(f"\n  GHSA ID: {adv['ghsa_id']}")
                print(f"  Severity: {adv['severity']}")
                print(f"  Summary: {adv['summary']}")
                print(f"  Vulnerable versions: {adv['vulnerable_range']}")
                print(f"  Fixed in: {adv['first_patched_version'] or 'No fix available'}")
                print(f"  CVSS Score: {adv['cvss_score']}")
        else:
            print(f"No security advisories found for {package} version {version}")