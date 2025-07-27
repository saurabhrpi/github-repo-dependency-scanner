"""
Dependency Parser for GitHub Repository Scanner

This module parses dependencies from source code files and package configuration files,
categorizing them into three types:
1. Direct imports (from module import function)
2. Relative imports (from .local_module import something)
3. External package dependencies (requirements.txt, package.json, etc.)
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import config


class DependencyParser:
    """Parser for extracting dependencies from source code and configuration files."""
    
    def __init__(self):
        self.import_patterns = config.IMPORT_PATTERNS
        self.package_patterns = config.PACKAGE_DEPENDENCY_PATTERNS
        self.package_files = config.PACKAGE_DEPENDENCY_FILES
    
    def parse_file_dependencies(self, file_path: str, content: str, language: str) -> List[Dict]:
        """
        Parse dependencies from a source code file.
        
        Args:
            file_path: Path to the file
            content: File content
            language: Programming language
            
        Returns:
            List of dependency dictionaries
        """
        dependencies = []
        
        if language not in self.import_patterns:
            return dependencies
        
        language_patterns = self.import_patterns[language]
        
        # Parse direct imports
        if 'direct_imports' in language_patterns:
            direct_deps = self._parse_direct_imports(content, language_patterns['direct_imports'], file_path)
            dependencies.extend(direct_deps)
        
        # Parse relative imports
        if 'relative_imports' in language_patterns:
            relative_deps = self._parse_relative_imports(content, language_patterns['relative_imports'], file_path)
            dependencies.extend(relative_deps)
        
        return dependencies
    
    def parse_package_dependencies(self, file_path: str, content: str) -> List[Dict]:
        """
        Parse dependencies from package configuration files.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            List of package dependency dictionaries
        """
        dependencies = []
        file_name = Path(file_path).name
        
        if file_name in self.package_patterns:
            patterns = self.package_patterns[file_name]
            dependencies = self._parse_package_file(content, patterns, file_path, file_name)
        
        return dependencies
    
    def _parse_direct_imports(self, content: str, patterns: List[str], file_path: str) -> List[Dict]:
        """Parse direct import statements."""
        dependencies = []
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    import_name = match.group(1)
                    if import_name and not self._is_standard_library(import_name):
                        # Mark as direct_import - the Neo4j manager will try to resolve it
                        # If it can't find a local file, it will create an external dependency
                        dependencies.append({
                            'source_file': file_path,
                            'import_name': import_name,
                            'import_statement': line,
                            'line_number': line_num,
                            'dependency_type': 'direct_import',
                            'dependency_category': 'direct_imports'
                        })
        
        return dependencies
    
    def _parse_relative_imports(self, content: str, patterns: List[str], file_path: str) -> List[Dict]:
        """Parse relative import statements."""
        dependencies = []
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    import_name = match.group(1)
                    if import_name:
                        # For Java, package declarations are NOT dependencies - they're namespace declarations
                        # Skip package declarations as they don't represent actual dependencies
                        if 'package' in line:
                            # This is a Java package declaration - skip it
                            continue
                        else:
                            # Try to resolve relative path for other languages
                            resolved_path = self._resolve_relative_path(file_path, import_name)
                            if resolved_path:
                                dependencies.append({
                                    'source_file': file_path,
                                    'import_name': import_name,
                                    'resolved_path': resolved_path,
                                    'import_statement': line,
                                    'line_number': line_num,
                                    'dependency_type': 'relative_import',
                                    'dependency_category': 'relative_imports'
                                })
        
        return dependencies
    
    def _parse_package_file(self, content: str, patterns: List[str], file_path: str, file_name: str) -> List[Dict]:
        """Parse package configuration files."""
        dependencies = []
        
        if file_name == 'package.json':
            # Handle JSON format
            try:
                data = json.loads(content)
                deps = data.get('dependencies', {})
                dev_deps = data.get('devDependencies', {})
                
                for package_name, version in deps.items():
                    dependencies.append({
                        'source_file': file_path,
                        'package_name': package_name,
                        'package_version': version,
                        'package_manager': 'npm',
                        'dependency_type': 'package_dependency',
                        'dependency_category': 'external_dependencies'
                    })
                
                for package_name, version in dev_deps.items():
                    dependencies.append({
                        'source_file': file_path,
                        'package_name': package_name,
                        'package_version': version,
                        'package_manager': 'npm',
                        'dependency_type': 'package_dependency',
                        'dependency_category': 'external_dependencies',
                        'is_dev_dependency': True
                    })
            except json.JSONDecodeError:
                pass
        
        elif file_name == 'requirements.txt':
            # Handle requirements.txt format
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                for pattern in patterns:
                    match = re.match(pattern, line)
                    if match:
                        package_name = match.group(1)
                        version = match.group(2) if len(match.groups()) > 1 else None
                        
                        dependencies.append({
                            'source_file': file_path,
                            'package_name': package_name,
                            'package_version': version,
                            'package_manager': 'pip',
                            'dependency_type': 'package_dependency',
                            'dependency_category': 'external_dependencies',
                            'line_number': line_num
                        })
                        break
        
        elif file_name == 'pom.xml':
            # Handle Maven XML format
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.DOTALL)
                for match in matches:
                    if len(match.groups()) >= 3:
                        group_id = match.group(1)
                        artifact_id = match.group(2)
                        version = match.group(3)
                        package_name = f"{group_id}:{artifact_id}"
                        
                        dependencies.append({
                            'source_file': file_path,
                            'package_name': package_name,
                            'package_version': version,
                            'package_manager': 'maven',
                            'dependency_type': 'package_dependency',
                            'dependency_category': 'external_dependencies'
                        })
        
        elif file_name in ['build.gradle', 'build.gradle.kts']:
            # Handle Gradle format
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    package_name = match.group(1)
                    
                    dependencies.append({
                        'source_file': file_path,
                        'package_name': package_name,
                        'package_version': None,  # Gradle often doesn't specify versions in build files
                        'package_manager': 'gradle',
                        'dependency_type': 'package_dependency',
                        'dependency_category': 'external_dependencies'
                    })
        
        return dependencies
    
    def _resolve_relative_path(self, source_file: str, relative_import: str) -> Optional[str]:
        """Resolve a relative import to an absolute file path."""
        try:
            source_path = Path(source_file)
            source_dir = source_path.parent
            
            # Handle different relative import patterns
            if relative_import.startswith('.'):
                # Python-style relative imports
                parts = relative_import.split('.')
                dots = len([p for p in parts if p == ''])
                
                if dots == 1:  # from .module import
                    target_path = source_dir / f"{parts[1]}.py"
                elif dots == 2:  # from ..module import
                    target_path = source_dir.parent / f"{parts[2]}.py"
                elif dots == 3:  # from ...module import
                    target_path = source_dir.parent.parent / f"{parts[3]}.py"
                else:
                    return None
                
                return str(target_path)
            
            elif relative_import.startswith('./') or relative_import.startswith('../'):
                # JavaScript/TypeScript-style relative imports
                target_path = source_dir / relative_import
                return str(target_path)
            
            # For Python relative imports without dots (already stripped by regex)
            # This handles cases like "from .app import Flask" -> relative_import = "app"
            # e.g., "from .sansio.scaffold import something" -> relative_import = "sansio.scaffold"
            else:
                # This handles Python relative imports where the leading dot was stripped by regex
                # e.g., "from .app import Flask" -> relative_import = "app"
                # e.g., "from .sansio.scaffold import something" -> relative_import = "sansio.scaffold"
                module_path_parts = relative_import.split('.')
                
                # Check if the first part of the import matches the current directory name
                # This happens when we're in a package and importing from a submodule
                # e.g., in src/flask/sansio/__init__.py doing "from .sansio.scaffold"
                if module_path_parts and source_dir.name == module_path_parts[0]:
                    # The import is referring to the current package, don't duplicate it
                    # Skip the first part and build from current directory
                    target_path = source_dir
                    for i, part in enumerate(module_path_parts[1:]):
                        if i == len(module_path_parts[1:]) - 1:
                            # Last part is the file name
                            target_path = target_path / f"{part}.py"
                        else:
                            # Intermediate parts are directories
                            target_path = target_path / part
                else:
                    # Normal case: build path from current directory
                    target_path = source_dir
                    for i, part in enumerate(module_path_parts):
                        if i == len(module_path_parts) - 1:
                            # Last part is the file name
                            target_path = target_path / f"{part}.py"
                        else:
                            # Intermediate parts are directories
                            target_path = target_path / part
                
                return str(target_path)
            
        except Exception:
            pass
        
        return None
    
    def _is_standard_library(self, import_name: str) -> bool:
        """Check if an import is from the standard library."""
        # Common standard library modules for different languages
        python_stdlib = {
            'os', 'sys', 're', 'json', 'datetime', 'pathlib', 'typing',
            'collections', 'itertools', 'functools', 'logging', 'argparse'
        }
        
        java_stdlib = {
            'java.lang', 'java.util', 'java.io', 'java.net', 'java.math'
        }
        
        js_stdlib = {
            'fs', 'path', 'http', 'https', 'url', 'querystring', 'crypto'
        }
        
        # Check Python standard library
        if import_name in python_stdlib:
            return True
        
        # Check Java standard library
        if any(import_name.startswith(lib) for lib in java_stdlib):
            return True
        
        # Check JavaScript standard library
        if import_name in js_stdlib:
            return True
        
        return False
    
    def get_dependency_statistics(self, dependencies: List[Dict]) -> Dict:
        """Get statistics about parsed dependencies."""
        stats = {
            'total_dependencies': len(dependencies),
            'direct_imports': 0,
            'relative_imports': 0,
            'external_dependencies': 0,
            'package_dependencies': 0,
            'by_language': {},
            'by_package_manager': {}
        }
        
        for dep in dependencies:
            dep_type = dep.get('dependency_type', 'unknown')
            dep_category = dep.get('dependency_category', 'unknown')
            
            if dep_type == 'direct_import':
                stats['direct_imports'] += 1
            elif dep_type == 'relative_import':
                stats['relative_imports'] += 1
            elif dep_type == 'external_dependency':
                stats['external_dependencies'] += 1
            elif dep_type == 'package_dependency':
                stats['package_dependencies'] += 1
            
            # Count by package manager
            package_manager = dep.get('package_manager')
            if package_manager:
                stats['by_package_manager'][package_manager] = stats['by_package_manager'].get(package_manager, 0) + 1
        
        return stats 