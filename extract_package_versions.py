import re
import os
import sys
from typing import Dict, List, Tuple
from pathlib import Path

# Use built-in tomllib for Python 3.11+ or fallback to toml
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        import toml as tomllib

def parse_requirements_txt(file_path: str) -> Dict[str, str]:
    """
    Parse requirements.txt file and extract package versions.
    
    Returns:
        Dict mapping package names to versions
    """
    packages = {}
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Match various version specifiers
                # Examples: package==1.2.3, package>=1.2.3, package~=1.2.3
                match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([0-9\.]+.*)', line)
                if match:
                    package_name = match.group(1).lower()
                    version_spec = match.group(2)
                    version = match.group(3)
                    
                    # For simplicity, store the version regardless of operator
                    # In production, you might want to handle version ranges
                    packages[package_name] = version
                else:
                    # Package without version
                    package_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
                    if package_match:
                        packages[package_match.group(1).lower()] = "Unknown"
    
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    
    return packages


def parse_pyproject_toml(file_path: str) -> Dict[str, str]:
    """
    Parse pyproject.toml file and extract package versions.
    
    Returns:
        Dict mapping package names to versions
    """
    packages = {}
    
    try:
        # tomllib requires binary mode
        if hasattr(tomllib, 'load'):
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
        else:
            # Old toml library uses text mode
            data = tomllib.load(file_path)
        
        # Check project.dependencies
        if 'project' in data and 'dependencies' in data['project']:
            for dep in data['project']['dependencies']:
                # Parse dependency strings like "flask>=2.0.0"
                match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([0-9\.]+.*)', dep)
                if match:
                    package_name = match.group(1).lower()
                    version = match.group(3)
                    packages[package_name] = version
                else:
                    # Package without version
                    package_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', dep)
                    if package_match:
                        packages[package_match.group(1).lower()] = "Unknown"
        
        # Check optional dependencies
        if 'project' in data and 'optional-dependencies' in data['project']:
            for group, deps in data['project']['optional-dependencies'].items():
                for dep in deps:
                    match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([0-9\.]+.*)', dep)
                    if match:
                        package_name = match.group(1).lower()
                        version = match.group(3)
                        packages[package_name] = version
                    else:
                        package_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', dep)
                        if package_match:
                            packages[package_match.group(1).lower()] = "Unknown"
        
        # Check dependency-groups (new PEP 735 format)
        if 'dependency-groups' in data:
            for group, deps in data['dependency-groups'].items():
                for dep in deps:
                    if isinstance(dep, str):
                        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([0-9\.]+.*)', dep)
                        if match:
                            package_name = match.group(1).lower()
                            version = match.group(3)
                            packages[package_name] = version
                        else:
                            package_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', dep)
                            if package_match:
                                packages[package_match.group(1).lower()] = "Unknown"
        
        # Check tool.poetry.dependencies if it's a Poetry project
        if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
            for pkg, version_spec in data['tool']['poetry']['dependencies'].items():
                if pkg.lower() != 'python':  # Skip Python version requirement
                    if isinstance(version_spec, str):
                        # Remove caret, tilde, etc.
                        version = re.sub(r'^[\^~]', '', version_spec)
                        packages[pkg.lower()] = version
                    elif isinstance(version_spec, dict) and 'version' in version_spec:
                        version = re.sub(r'^[\^~]', '', version_spec['version'])
                        packages[pkg.lower()] = version
                    else:
                        packages[pkg.lower()] = "Unknown"
    
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    
    return packages


def get_flask_package_versions() -> Dict[str, str]:
    """
    Get package versions from the Flask repository in flask-main directory.
    
    Returns:
        Dict mapping package names to versions
    """
    flask_repo_path = r"C:\Users\meets\AI Bootcamp\github-repo-dependency-scanner\flask-main"
    all_packages = {}
    
    # Search for requirements.txt files in flask-main
    for root, dirs, files in os.walk(flask_repo_path):
        for file in files:
            if file.startswith('requirements') and file.endswith('.txt'):
                file_path = os.path.join(root, file)
                packages = parse_requirements_txt(file_path)
                # Update with new packages or newer versions
                for pkg, version in packages.items():
                    if pkg not in all_packages or version != "Unknown":
                        all_packages[pkg] = version
    
    # Search for pyproject.toml files in flask-main
    for root, dirs, files in os.walk(flask_repo_path):
        if 'pyproject.toml' in files:
            file_path = os.path.join(root, 'pyproject.toml')
            packages = parse_pyproject_toml(file_path)
            # Update with new packages or newer versions
            for pkg, version in packages.items():
                if pkg not in all_packages or version != "Unknown":
                    all_packages[pkg] = version
    
    return all_packages


if __name__ == "__main__":
    # Test the function
    versions = get_flask_package_versions()
    
    print(f"Found {len(versions)} packages with versions in Flask repository:\n")
    
    # Show first 20 packages
    for i, (pkg, version) in enumerate(sorted(versions.items())[:20]):
        print(f"  {pkg}: {version}")
    
    if len(versions) > 20:
        print(f"  ... and {len(versions) - 20} more")