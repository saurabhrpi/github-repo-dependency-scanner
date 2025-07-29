"""
Upgrade Analyzer - Finds safe upgrade paths for vulnerable dependencies using LLM.

This module analyzes the vulnerability impact report and uses LLM to:
1. Identify the safest upgrade candidates
2. Predict potential breaking changes
3. Generate rollback instructions
4. Create test checklists
5. Suggest alternative libraries when no safe upgrade exists
"""

from typing import List, Dict, Tuple, Optional, Set, Any
from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
import json
import re
from dataclasses import dataclass
from packaging import version
import requests
import openai
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError


@dataclass
class UpgradeRecommendation:
    """LLM-generated upgrade recommendation."""
    package: str
    current_version: str
    recommended_version: Optional[str]
    upgrade_type: str  # "direct_upgrade", "alternative_library", "manual_mitigation"
    instructions: List[str]
    rollback_steps: List[str]
    test_checklist: List[str]
    breaking_changes: List[str]
    confidence_score: float
    reasoning: str
    alternative_libraries: List[Dict[str, str]] = None


class UpgradeAnalyzer:
    """Analyzes vulnerable dependencies and uses LLM to recommend safe upgrade paths."""
    
    def __init__(self, neo4j_uri: str = NEO4J_URI, neo4j_user: str = NEO4J_USER,
                 neo4j_password: str = NEO4J_PASSWORD, openai_api_key: Optional[str] = None,
                 llm_timeout: int = 60):
        """
        Initialize the upgrade analyzer.
        
        Args:
            neo4j_uri: Neo4j database URI
            neo4j_user: Database username
            neo4j_password: Database password
            openai_api_key: OpenAI API key
            llm_timeout: Timeout for LLM calls in seconds
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        # Initialize OpenAI client
        api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        if api_key:
            self.llm_client = openai.OpenAI(api_key=api_key)
        else:
            raise ValueError("OpenAI API key is required for upgrade analysis.")
        
        self.llm_timeout = llm_timeout
        self.executor = ThreadPoolExecutor(max_workers=3)
    
    def close(self):
        """Close database connection and executor."""
        self.driver.close()
        self.executor.shutdown()
    
    def query_available_versions(self, package_name: str) -> List[str]:
        """Query package registry for available versions."""
        try:
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                versions = list(data.get("releases", {}).keys())
                # Sort versions properly
                try:
                    versions.sort(key=lambda v: version.parse(v), reverse=True)
                except:
                    versions.sort(reverse=True)
                return versions
        except Exception as e:
            print(f"  Error querying PyPI for {package_name}: {e}")
        
        return []
    
    def get_package_usage_context(self, package_name: str) -> Dict[str, Any]:
        """Get how the package is used in the codebase from Neo4j."""
        with self.driver.session() as session:
            # Get import patterns and affected files
            query = """
            MATCH (f:File)-[r:EXTERNAL_DEPENDENCIES]->(m:Module)
            WHERE m.name = $package_name
            RETURN f.path as file_path,
                   r.import_statement as import_statement,
                   r.line_number as line_number,
                   f.type as file_type
            """
            
            result = session.run(query, package_name=package_name)
            
            usage_context = {
                "affected_files": [],
                "import_patterns": set(),
                "specific_imports": set(),
                "file_types": set()
            }
            
            for record in result:
                usage_context["affected_files"].append(record["file_path"])
                usage_context["import_patterns"].add(record["import_statement"])
                
                # Extract specific imports from the import statement itself
                import_stmt = record["import_statement"]
                if "from" in import_stmt and "import" in import_stmt:
                    # Parse "from module import X, Y, Z" patterns
                    parts = import_stmt.split("import", 1)
                    if len(parts) > 1:
                        imports = parts[1].strip()
                        # Handle multiple imports separated by commas
                        for imp in imports.split(','):
                            imp = imp.strip()
                            if imp and not imp.startswith('('):
                                usage_context["specific_imports"].add(imp)
                
                if record["file_type"]:
                    usage_context["file_types"].add(record["file_type"])
            
            # Convert sets to lists for JSON serialization
            usage_context["import_patterns"] = list(usage_context["import_patterns"])
            usage_context["specific_imports"] = list(usage_context["specific_imports"])
            usage_context["file_types"] = list(usage_context["file_types"])
            
            return usage_context
    
    def build_upgrade_analysis_prompt(self, package_name: str, current_version: str,
                                    available_versions: List[str], 
                                    advisories: List[Dict[str, Any]],
                                    usage_context: Dict[str, Any]) -> str:
        """Build prompt for LLM to analyze upgrade options."""
        
        # Get newer versions only
        try:
            current_ver = version.parse(current_version)
            newer_versions = [v for v in available_versions[:10] 
                            if version.parse(v) > current_ver][:5]  # Top 5 newer versions
        except:
            newer_versions = available_versions[:5]
        
        # Format advisories with fixed version info
        advisory_summary = "\n".join([
            f"- {adv.get('cve_id', adv.get('ghsa_id', adv.get('id', 'Unknown')))}: "
            f"CVSS {adv.get('cvss_score', 'N/A')} - {adv.get('summary', 'No description')[:100]}"
            f"\n  Fixed in: {adv.get('fixed_version', 'Unknown')} | Vulnerable range: {adv.get('vulnerable_range', 'Unknown')}"
            for adv in advisories[:5]  # Limit to 5 advisories
        ])
        
        # Format usage context
        import_examples = "\n".join(usage_context["import_patterns"][:5])
        affected_files_count = len(usage_context["affected_files"])
        specific_imports = ", ".join(usage_context["specific_imports"][:10])
        
        prompt = f"""Analyze upgrade options for the vulnerable package {package_name} version {current_version}.

VULNERABILITY CONTEXT:
{advisory_summary}

CURRENT USAGE IN CODEBASE:
- Affected files: {affected_files_count} files
- Import patterns:
{import_examples}
- Specific imports used: {specific_imports or "None (full module imports)"}

AVAILABLE UPGRADE VERSIONS:
{json.dumps(newer_versions, indent=2)}

ANALYSIS REQUIRED:
1. Recommend the SAFEST upgrade path considering:
   - Which version fixes the vulnerabilities
   - Minimal breaking changes
   - Compatibility with the import patterns shown above

2. If NO safe direct upgrade exists, suggest alternative libraries with similar APIs.

3. Provide specific, actionable instructions.

Please respond with a JSON object in this exact format:
{{
    "recommended_version": "version number or null if no safe upgrade",
    "upgrade_type": "direct_upgrade" or "alternative_library" or "manual_mitigation",
    "confidence_score": 0.0 to 1.0,
    "reasoning": "Brief explanation of your recommendation",
    "breaking_changes": ["List of potential breaking changes"],
    "instructions": ["Step-by-step upgrade instructions"],
    "rollback_steps": ["How to rollback if issues occur"],
    "test_checklist": ["Specific tests to run based on usage patterns"],
    "alternative_libraries": [
        {{"name": "library_name", "version": "version", "migration_effort": "low/medium/high"}}
    ]
}}

Be specific and practical in your recommendations. Consider the actual usage patterns in the codebase."""
        
        return prompt
    
    def analyze_package_upgrade(self, package_name: str, current_version: str,
                              advisories: List[Dict[str, Any]]) -> UpgradeRecommendation:
        """Use LLM to analyze and recommend upgrade path for a package."""
        print(f"  Analyzing upgrade options for {package_name} {current_version}...")
        
        # Get available versions
        available_versions = self.query_available_versions(package_name)
        if not available_versions:
            print(f"    No versions found in registry")
            return self._create_manual_mitigation(package_name, current_version, advisories)
        
        # Get usage context from Neo4j
        usage_context = self.get_package_usage_context(package_name)
        
        # Build prompt
        prompt = self.build_upgrade_analysis_prompt(
            package_name, current_version, available_versions, advisories, usage_context
        )
        
        try:
            # Call LLM with timeout
            future = self.executor.submit(self._llm_analyze, prompt)
            response = future.result(timeout=self.llm_timeout)
            
            # Parse response
            return self._parse_llm_recommendation(package_name, current_version, response)
            
        except TimeoutError:
            raise RuntimeError(f"LLM timeout after {self.llm_timeout} seconds for {package_name}")
        except Exception as e:
            raise RuntimeError(f"LLM analysis failed for {package_name}: {e}")
    
    def _llm_analyze(self, prompt: str) -> str:
        """Call LLM for analysis (runs in separate thread)."""
        response = self.llm_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a security expert specializing in dependency management and vulnerability remediation."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=2000
        )
        
        return response.choices[0].message.content
    
    def _parse_llm_recommendation(self, package_name: str, current_version: str,
                                 llm_response: str) -> UpgradeRecommendation:
        """Parse LLM response into UpgradeRecommendation."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                raise ValueError("No JSON found in LLM response")
            
            return UpgradeRecommendation(
                package=package_name,
                current_version=current_version,
                recommended_version=data.get("recommended_version"),
                upgrade_type=data.get("upgrade_type", "direct_upgrade"),
                instructions=data.get("instructions", []),
                rollback_steps=data.get("rollback_steps", []),
                test_checklist=data.get("test_checklist", []),
                breaking_changes=data.get("breaking_changes", []),
                confidence_score=float(data.get("confidence_score", 0.5)),
                reasoning=data.get("reasoning", ""),
                alternative_libraries=data.get("alternative_libraries", [])
            )
            
        except Exception as e:
            raise RuntimeError(f"Failed to parse LLM response for {package_name}: {e}")
    
    def _create_manual_mitigation(self, package_name: str, current_version: str,
                                 advisories: List[Dict[str, Any]]) -> UpgradeRecommendation:
        """Create manual mitigation recommendation when no upgrade available."""
        return UpgradeRecommendation(
            package=package_name,
            current_version=current_version,
            recommended_version=None,
            upgrade_type="manual_mitigation",
            instructions=[
                f"No upgrade available for {package_name}",
                "Review code for vulnerable usage patterns",
                "Consider implementing security controls around vulnerable functions"
            ],
            rollback_steps=[],
            test_checklist=["Audit all usages of this package"],
            breaking_changes=[],
            confidence_score=0.5,
            reasoning="No newer versions available - manual mitigation required"
        )
    
    def get_dependency_chains(self, package_name: str, file_path: str) -> List[str]:
        """Get the dependency chain showing how a file depends on a vulnerable package."""
        chains = []
        
        with self.driver.session() as session:
            # Find import chains
            query = """
            MATCH path = (f1:File {path: $file_path})-[:DIRECT_IMPORTS|RELATIVE_IMPORTS*1..3]->(f2:File)-[:EXTERNAL_DEPENDENCIES]->(m:Module {name: $package_name})
            RETURN [n in nodes(path) WHERE n:File | n.path] as chain
            LIMIT 5
            """
            
            result = session.run(query, file_path=file_path, package_name=package_name)
            
            for record in result:
                chain = record["chain"]
                if chain:
                    chains.append(" → ".join(chain))
            
            # If no indirect chains, check direct dependency
            if not chains:
                direct_query = """
                MATCH (f:File {path: $file_path})-[:EXTERNAL_DEPENDENCIES]->(m:Module {name: $package_name})
                RETURN f.path as file
                """
                result = session.run(direct_query, file_path=file_path, package_name=package_name)
                if result.single():
                    chains.append(f"{file_path} → {package_name} (direct)")
        
        return chains
    
    def generate_before_after_analysis(self, package_name: str, current_version: str, 
                                     recommended_version: str, advisories: List[Dict]) -> Dict[str, Any]:
        """Generate before/after analysis for the upgrade."""
        
        # Count vulnerabilities by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        for adv in advisories:
            severity = adv.get("severity", "MODERATE")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine which vulnerabilities will be fixed
        fixed_vulns = []
        remaining_vulns = []
        
        for adv in advisories:
            fixed_version = adv.get("fixed_version", "")
            if fixed_version and recommended_version >= fixed_version:
                fixed_vulns.append(adv)
            else:
                remaining_vulns.append(adv)
        
        return {
            "before": {
                "version": current_version,
                "total_vulnerabilities": len(advisories),
                "severity_distribution": severity_counts,
                "cvss_scores": [adv.get("cvss_score", 0) for adv in advisories]
            },
            "after": {
                "version": recommended_version,
                "vulnerabilities_fixed": len(fixed_vulns),
                "vulnerabilities_remaining": len(remaining_vulns),
                "fixed_cves": [adv.get("ghsa_id", adv.get("cve_id", "Unknown")) for adv in fixed_vulns],
                "remaining_cves": [adv.get("ghsa_id", adv.get("cve_id", "Unknown")) for adv in remaining_vulns]
            },
            "improvement_percentage": (len(fixed_vulns) / len(advisories) * 100) if advisories else 0
        }
    
    def generate_comprehensive_report(self, vulnerability_report_path: str = "vulnerability_impact_report.json",
                                    output_path: str = "comprehensive_vulnerability_report.json") -> Dict[str, Any]:
        """
        Generate comprehensive vulnerability remediation report with LLM analysis.
        
        Args:
            vulnerability_report_path: Path to vulnerability impact report
            output_path: Path to save the comprehensive report
            
        Returns:
            Comprehensive report with affected files, dependency chains, and remediation plans
        """
        # Load vulnerability report
        with open(vulnerability_report_path, 'r') as f:
            vuln_report = json.load(f)
        
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE VULNERABILITY REPORT")
        print("="*60)
        
        # Load vulnerable packages info
        advisory_map = {}
        try:
            with open("vulnerable_packages.json", 'r') as f:
                vuln_packages_data = json.load(f)
                # Handle the actual structure of vulnerable_packages.json
                if "vulnerable_packages" in vuln_packages_data:
                    for pkg_info in vuln_packages_data["vulnerable_packages"]:
                        pkg_name = pkg_info["package"]
                        advisories = pkg_info.get("advisories", [])
                        advisory_map[pkg_name] = advisories
                else:
                    # Fallback for old format (if it was a simple list)
                    for pkg_name, pkg_version, advisories in vuln_packages_data:
                        advisory_map[pkg_name] = advisories
        except Exception as e:
            print(f"Warning: Could not load vulnerable_packages.json: {e}")
            advisory_map = {}
        
        # Initialize comprehensive report structure
        comprehensive_report = {
            "executive_summary": {
                "total_vulnerable_packages": vuln_report["summary"]["total_vulnerable_packages"],
                "total_affected_files": vuln_report["summary"]["total_impacted_files"],
                "remediation_available": 0,  # Will be updated
                "estimated_effort": "low",  # Will be updated
                "high_priority_files": vuln_report["summary"]["high_priority_files"]
            },
            "vulnerability_details": []
        }
        
        direct_upgrades = 0
        alternative_libraries = 0
        manual_mitigations = 0
        
        # Analyze each vulnerable package
        for i, package_impact in enumerate(vuln_report["package_impacts"]):
            package_name = package_impact["package"]
            current_version = package_impact["version"]
            
            print(f"\nAnalyzing {package_name} {current_version}...")
            
            # Get advisories for this package
            advisories = advisory_map.get(package_name, [])
            
            # Get LLM recommendation
            recommendation = self.analyze_package_upgrade(
                package_name, current_version, advisories
            )
            
            # Count recommendation types
            if recommendation.upgrade_type == "direct_upgrade":
                direct_upgrades += 1
            elif recommendation.upgrade_type == "alternative_library":
                alternative_libraries += 1
            else:
                manual_mitigations += 1
            
            print(f"  Recommendation: {recommendation.upgrade_type}")
            print(f"  Confidence: {recommendation.confidence_score:.2f}")
            if recommendation.recommended_version:
                print(f"  Upgrade to: {recommendation.recommended_version}")
            
            # Create detailed vulnerability entry
            vuln_detail = {
                "package": package_name,
                "current_version": current_version,
                "vulnerability_summary": {
                    "advisory_count": package_impact["advisory_count"],
                    "max_cvss_score": package_impact["max_cvss"],
                    "vulnerabilities": [
                        {
                            "id": adv.get("ghsa_id", adv.get("cve_id", "Unknown")),
                            "severity": adv.get("severity", "MODERATE"),
                            "cvss_score": adv.get("cvss_score", 0),
                            "summary": adv.get("summary", ""),
                            "fixed_in": adv.get("fixed_version", "Unknown")
                        }
                        for adv in advisories[:5]  # Limit to 5
                    ]
                },
                "affected_files_ranked": []
            }
            
            # Add affected files with dependency chains
            for file_info in sorted(package_impact["impacted_files"], 
                                   key=lambda x: x["priority_score"], reverse=True):
                
                file_detail = {
                    "file_path": file_info["file_path"],
                    "impact_score": file_info["priority_score"],
                    "import_statement": file_info["import_line"],
                    "line_number": file_info["line_number"],
                    "dependency_chains": self.get_dependency_chains(package_name, file_info["file_path"]),
                    "file_category": "critical" if file_info["priority_score"] >= 8 else 
                                   "high" if file_info["priority_score"] >= 6 else "medium"
                }
                vuln_detail["affected_files_ranked"].append(file_detail)
            
            # Add remediation recommendation
            vuln_detail["remediation"] = {
                "recommended_action": recommendation.upgrade_type,
                "target_version": recommendation.recommended_version,
                "confidence": recommendation.confidence_score,
                "ai_reasoning": recommendation.reasoning,
                "urgency": "high" if package_impact["max_cvss"] >= 7 else "medium",
                "implementation_steps": recommendation.instructions,
                "rollback_plan": recommendation.rollback_steps,
                "testing_checklist": recommendation.test_checklist,
                "potential_breaking_changes": recommendation.breaking_changes
            }
            
            # Add before/after analysis if upgrade is recommended
            if recommendation.recommended_version:
                vuln_detail["before_after_analysis"] = self.generate_before_after_analysis(
                    package_name, current_version, recommendation.recommended_version, advisories
                )
            
            # Add alternative libraries if suggested
            if recommendation.alternative_libraries:
                vuln_detail["alternative_libraries"] = recommendation.alternative_libraries
            
            comprehensive_report["vulnerability_details"].append(vuln_detail)
        
        # Update executive summary
        comprehensive_report["executive_summary"]["remediation_available"] = direct_upgrades
        comprehensive_report["executive_summary"]["estimated_effort"] = self._estimate_comprehensive_effort(
            direct_upgrades, alternative_libraries, manual_mitigations, 
            sum(len(v["remediation"]["potential_breaking_changes"]) for v in comprehensive_report["vulnerability_details"])
        )
        
        # Add implementation roadmap
        comprehensive_report["implementation_roadmap"] = {
            "priority_order": self._create_priority_order(comprehensive_report["vulnerability_details"]),
            "phase_1_critical": [
                v["package"] for v in comprehensive_report["vulnerability_details"] 
                if v.get("vulnerability_summary", {}).get("max_cvss_score", 0) >= 7
            ],
            "phase_2_high": [
                v["package"] for v in comprehensive_report["vulnerability_details"] 
                if 5 <= v.get("vulnerability_summary", {}).get("max_cvss_score", 0) < 7
            ],
            "phase_3_medium": [
                v["package"] for v in comprehensive_report["vulnerability_details"] 
                if v.get("vulnerability_summary", {}).get("max_cvss_score", 0) < 5
            ]
        }
        
        # Save comprehensive report
        with open(output_path, 'w') as f:
            json.dump(comprehensive_report, f, indent=2)
        
        print(f"\nComprehensive report saved to: {output_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("COMPREHENSIVE VULNERABILITY REPORT SUMMARY")
        print("="*60)
        print(f"Total vulnerable packages: {comprehensive_report['executive_summary']['total_vulnerable_packages']}")
        print(f"Total affected files: {comprehensive_report['executive_summary']['total_affected_files']}")
        print(f"High priority files: {comprehensive_report['executive_summary']['high_priority_files']}")
        print(f"Remediation effort: {comprehensive_report['executive_summary']['estimated_effort']}")
        print(f"Direct upgrades available: {direct_upgrades}")
        print(f"Alternative libraries suggested: {alternative_libraries}")
        print(f"Manual mitigations required: {manual_mitigations}")
        
        print("\nReport includes:")
        print("✓ Complete list of affected files ranked by impact")
        print("✓ Dependency chains showing vulnerability propagation")
        print("✓ AI-powered risk assessment and urgency recommendations")
        print("✓ Before/after analysis of recommended changes")
        print("✓ Implementation roadmap with phased approach")
        
        return comprehensive_report
    
    def _create_priority_order(self, vulnerability_details: List[Dict[str, Any]]) -> List[str]:
        """Create priority order based on CVSS scores and confidence."""
        # Sort by CVSS score and confidence
        sorted_vulns = sorted(vulnerability_details, key=lambda v: (
            v["vulnerability_summary"]["max_cvss_score"],
            v["remediation"]["confidence"]
        ), reverse=True)
        
        return [
            f"{v['package']}: {v['current_version']} → "
            f"{v['remediation'].get('target_version', v['remediation']['recommended_action'])}"
            for v in sorted_vulns
        ]
    
    def _estimate_comprehensive_effort(self, direct_upgrades: int, alternatives: int, 
                                     mitigations: int, total_breaking_changes: int) -> str:
        """Estimate total effort based on recommendation types and breaking changes."""
        if alternatives > 2 or total_breaking_changes > 10:
            return "high"
        elif alternatives > 0 or total_breaking_changes > 5 or mitigations > 2:
            return "medium"
        else:
            return "low"


if __name__ == "__main__":
    analyzer = UpgradeAnalyzer()
    
    try:
        # Generate comprehensive report
        report = analyzer.generate_comprehensive_report()
        
        print("\nReview comprehensive_vulnerability_report.json for detailed analysis and recommendations.")
        
    finally:
        analyzer.close()