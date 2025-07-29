from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from typing import List, Tuple, Dict
from extract_package_versions import get_flask_package_versions

def get_external_dependencies() -> List[Tuple[str, str]]:
    """
    Connect to Neo4j and retrieve all external dependencies (modules) with versions.
    
    Returns:
        List of (module_name, version) tuples
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    modules = []
    
    # First, get version information from Flask project files
    package_versions = get_flask_package_versions()
    
    try:
        with driver.session() as session:
            # Query to get all Module nodes (external dependencies)
            query = """
            MATCH (m:Module)
            WHERE m.type = 'external_module'
            RETURN DISTINCT m.name AS module_name
            ORDER BY m.name
            """
            
            result = session.run(query)
            
            for record in result:
                module_name = record["module_name"]
                # Look up version from Flask project dependency files
                version = package_versions.get(module_name.lower(), "Unknown")
                modules.append((module_name, version))
            
    finally:
        driver.close()
    
    return modules

if __name__ == "__main__":
    # Test the function
    deps = get_external_dependencies()
    print(f"Found {len(deps)} external dependencies:\n")
    
    # Show dependencies with versions
    with_version = [(name, ver) for name, ver in deps if ver != "Unknown"]
    without_version = [(name, ver) for name, ver in deps if ver == "Unknown"]
    
    print(f"Dependencies with versions ({len(with_version)}):")
    for name, version in with_version[:10]:  # Show first 10
        print(f"  {name}: {version}")
    if len(with_version) > 10:
        print(f"  ... and {len(with_version) - 10} more")
    
    print(f"\nDependencies without versions ({len(without_version)}):")
    for name, version in without_version[:5]:  # Show first 5
        print(f"  {name}")
    if len(without_version) > 5:
        print(f"  ... and {len(without_version) - 5} more")