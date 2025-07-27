from typing import Dict, List, Optional
from neo4j import GraphDatabase
import config


class Neo4jManager:
    """Manages Neo4j database operations for dependency graphs."""
    
    def __init__(self, uri: str = None, user: str = None, password: str = None):
        """Initialize Neo4j manager.
        
        Args:
            uri: Neo4j database URI
            user: Database username
            password: Database password
        """
        self.uri = uri or config.NEO4J_URI
        self.user = user or config.NEO4J_USER
        self.password = password or config.NEO4J_PASSWORD
        self.driver = None
    
    def connect(self):
        """Connect to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            print("Successfully connected to Neo4j database")
        except Exception as e:
            print(f"Failed to connect to Neo4j: {e}")
            raise
    
    def disconnect(self):
        """Disconnect from Neo4j database."""
        if self.driver:
            self.driver.close()
            print("Disconnected from Neo4j database")
    
    def setup_database(self):
        """Set up database constraints and indexes."""
        with self.driver.session() as session:
            for query in config.CYPHER_QUERIES['create_constraints']:
                try:
                    session.run(query)
                    print(f"Executed: {query}")
                except Exception as e:
                    print(f"Warning: Could not create constraint: {e}")
    
    def clear_database(self):
        """Clear all data from the database."""
        with self.driver.session() as session:
            for query in config.CYPHER_QUERIES['clear_database']:
                session.run(query)
        print("Cleared all data from database")
    
    def create_file_node(self, file_info: Dict) -> bool:
        """Create a file node in the database.
        
        Args:
            file_info: File information dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.driver.session() as session:
                result = session.run(
                    config.CYPHER_QUERIES['create_file_node'],
                    path=file_info['path'],
                    name=file_info['name'],
                    extension=file_info.get('extension', ''),
                    language=file_info.get('language', 'unknown'),
                    size=file_info.get('size', 0),
                    last_modified=file_info.get('last_modified', '')
                )
                return True
        except Exception as e:
            print(f"Error creating file node for {file_info['path']}: {e}")
            return False
    
    def create_dependency_relationship(self, dependency: Dict) -> bool:
        """Create a dependency relationship between files.
        
        Args:
            dependency: Dependency information dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.driver.session() as session:
                dependency_type = dependency.get('dependency_type', 'unknown')
                
                if dependency_type == 'direct_import':
                    # Handle direct imports
                    target_path = self._find_target_file_path(dependency['import_name'])
                    if target_path:
                        # Prevent self-referential relationships
                        if target_path == dependency['source_file']:
                            print(f"Skipping self-referential dependency: {dependency['source_file']} -> {target_path}")
                            return False
                        
                        result = session.run(
                            config.CYPHER_QUERIES['create_direct_dependency'],
                            source_path=dependency['source_file'],
                            target_path=target_path,
                            import_statement=dependency['import_statement'],
                            line_number=dependency['line_number']
                        )
                    else:
                        # Create external module node for unresolved direct imports
                        result = session.run(
                            config.CYPHER_QUERIES['create_external_dependency'],
                            source_path=dependency['source_file'],
                            module_name=dependency['import_name'],
                            module_type='external_module',
                            import_statement=dependency['import_statement'],
                            line_number=dependency['line_number']
                        )
                
                elif dependency_type == 'relative_import':
                    # Handle relative imports
                    target_path = dependency.get('resolved_path')
                    if target_path:
                        # Verify that the resolved target file actually exists in the database
                        result = session.run("""
                            MATCH (f:File)
                            WHERE f.path = $target_path
                            RETURN f.path as path
                        """, target_path=target_path)
                        
                        if result.single():
                            # Target file exists - create relative dependency
                            # Prevent self-referential relationships
                            if target_path == dependency['source_file']:
                                print(f"Skipping self-referential dependency: {dependency['source_file']} -> {target_path}")
                                return False
                            
                            result = session.run(
                                config.CYPHER_QUERIES['create_relative_dependency'],
                                source_path=dependency['source_file'],
                                target_path=target_path,
                                import_statement=dependency['import_statement'],
                                line_number=dependency['line_number']
                            )
                        else:
                            # Target file doesn't exist in database - create external dependency
                            print(f"⚠️  Relative import target not found in database: {target_path}")
                            print(f"   Source: {dependency['source_file']}")
                            print(f"   Import: {dependency['import_statement']}")
                            print(f"   This is expected if the file wasn't scanned or doesn't exist")
                            result = session.run(
                                config.CYPHER_QUERIES['create_external_dependency'],
                                source_path=dependency['source_file'],
                                module_name=dependency['import_name'],
                                module_type='relative_module',
                                import_statement=dependency['import_statement'],
                                line_number=dependency['line_number']
                            )
                    else:
                        # No resolved path - create external module node for unresolved relative imports
                        result = session.run(
                            config.CYPHER_QUERIES['create_external_dependency'],
                            source_path=dependency['source_file'],
                            module_name=dependency['import_name'],
                            module_type='relative_module',
                            import_statement=dependency['import_statement'],
                            line_number=dependency['line_number']
                        )
                
                elif dependency_type == 'package_dependency':
                    # Handle package dependencies
                    result = session.run(
                        config.CYPHER_QUERIES['create_package_dependency'],
                        source_path=dependency['source_file'],
                        package_name=dependency['package_name'],
                        package_version=dependency.get('package_version'),
                        package_manager=dependency.get('package_manager', 'unknown'),
                        source_file=dependency['source_file']
                    )
                
                elif dependency_type == 'external_dependency':
                    # Handle external dependencies (legacy support)
                    result = session.run(
                        config.CYPHER_QUERIES['create_external_dependency'],
                        source_path=dependency['source_file'],
                        module_name=dependency['import_name'],
                        module_type=dependency.get('type', 'external_module'),
                        import_statement=dependency['import_statement'],
                        line_number=dependency['line_number']
                    )
                
                else:
                    print(f"Unknown dependency type: {dependency_type}")
                    return False
                
                return True
        except Exception as e:
            print(f"Error creating dependency for {dependency['source_file']}: {e}")
            return False
    
    def file_exists_in_database(self, file_path: str) -> bool:
        """Check if a file exists in the database.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (f:File)
                    WHERE f.path = $file_path
                    RETURN f.path as path
                """, file_path=file_path)
                
                return result.single() is not None
        except Exception as e:
            print(f"Error checking if file exists: {e}")
            return False

    def _find_target_file_path(self, import_name: str) -> Optional[str]:
        """Find the target file path for an import name.
        
        Args:
            import_name: Name of the imported module/class
            
        Returns:
            Target file path if found, None otherwise
        """
        try:
            with self.driver.session() as session:
                # For Java imports like "org.springframework.core.ClassPathResource"
                # We need to find the exact file that contains this class
                
                # Method 1: For Spring Framework imports, construct the exact expected path
                if import_name.startswith('org.springframework'):
                    parts = import_name.split('.')
                    if len(parts) >= 4:
                        # org.springframework.core.ClassPathResource -> 
                        # spring-core/src/main/java/org/springframework/core/ClassPathResource.java
                        module_name = parts[2]  # core, context, beans, etc.
                        package_path = '/'.join(parts[3:-1])  # org/springframework/core
                        class_name = parts[-1]  # ClassPathResource
                        
                        # Look for exact file match
                        expected_path = f"spring-{module_name}/src/main/java/{package_path}/{class_name}.java"
                        result = session.run("""
                            MATCH (f:File)
                            WHERE f.path = $expected_path
                            RETURN f.path as path
                        """, expected_path=expected_path)
                        
                        record = result.single()
                        if record:
                            return record['path']
                        
                        # If exact match not found, try partial match with class name at the end
                        result = session.run("""
                            MATCH (f:File)
                            WHERE f.path ENDS WITH $class_file
                            RETURN f.path as path
                            LIMIT 1
                        """, class_file=f"{class_name}.java")
                        
                        record = result.single()
                        if record:
                            return record['path']
                
                # Method 2: For other Java imports, try to find exact class file
                if '.' in import_name:
                    class_name = import_name.split('.')[-1]
                    
                    # Look for exact class file match
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.path ENDS WITH $class_file
                        RETURN f.path as path
                        LIMIT 1
                    """, class_file=f"{class_name}.java")
                    
                    record = result.single()
                    if record:
                        return record['path']
                
                # Method 3: For Python imports, try to find exact module file
                if not import_name.startswith('.'):  # Not a relative import
                    # Convert import name to file path
                    module_path = import_name.replace('.', '/')
                    
                    # For Python packages, first try to find the package directory's __init__.py
                    # This handles cases like "from flask import request" -> look for flask/__init__.py
                    # Should match: src/flask/__init__.py, flask/__init__.py, etc.
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.path ENDS WITH $init_file
                        RETURN f.path as path
                        LIMIT 1
                    """, init_file=f"{module_path}/__init__.py")
                    
                    record = result.single()
                    if record:
                        return record['path']
                    
                    # Also try to find the package directory itself (for cases where __init__.py might not be scanned)
                    # This handles cases where we have flask/ but no __init__.py in our scanned files
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.path CONTAINS $package_name AND f.path ENDS WITH '.py'
                        AND f.path CONTAINS $package_name
                        RETURN f.path as path
                        ORDER BY size(f.path) ASC
                        LIMIT 1
                    """, package_name=import_name)
                    
                    record = result.single()
                    if record:
                        return record['path']
                    
                    # If no package found, try to find a standalone .py file
                    # This handles cases like "from mymodule import something" -> look for mymodule.py
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.path ENDS WITH $module_file
                        RETURN f.path as path
                        LIMIT 1
                    """, module_file=f"{module_path}.py")
                    
                    record = result.single()
                    if record:
                        return record['path']
                    
                    # Try exact module name match as fallback
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.name = $module_name
                        RETURN f.path as path
                        LIMIT 1
                    """, module_name=f"{import_name}.py")
                    
                    record = result.single()
                    if record:
                        return record['path']
                
                return None
                
        except Exception as e:
            print(f"Error finding target file for {import_name}: {e}")
            return None
    
    def list_files_in_database(self, pattern: str = None) -> List[str]:
        """List all files in the database, optionally filtered by pattern.
        
        Args:
            pattern: Optional pattern to filter files (e.g., "sansio" to find all files containing "sansio")
            
        Returns:
            List of file paths
        """
        try:
            with self.driver.session() as session:
                if pattern:
                    result = session.run("""
                        MATCH (f:File)
                        WHERE f.path CONTAINS $pattern
                        RETURN f.path as path
                        ORDER BY f.path
                    """, pattern=pattern)
                else:
                    result = session.run("""
                        MATCH (f:File)
                        RETURN f.path as path
                        ORDER BY f.path
                    """)
                
                return [record['path'] for record in result]
        except Exception as e:
            print(f"Error listing files: {e}")
            return []

    def get_dependency_statistics(self) -> Dict:
        """Get statistics about the dependency graph.
        
        Returns:
            Dictionary with statistics
        """
        with self.driver.session() as session:
            stats = {}
            
            # Total files
            result = session.run("MATCH (f:File) RETURN count(f) as count")
            stats['total_files'] = result.single()['count']
            
            # Files by language
            result = session.run("""
                MATCH (f:File)
                RETURN f.language as language, count(f) as count
                ORDER BY count DESC
            """)
            stats['files_by_language'] = {record['language']: record['count'] for record in result}
            
            # Total dependencies (sum of all relationship types)
            result = session.run("""
                MATCH ()-[r:DIRECT_IMPORTS]->() RETURN count(r) as count
                UNION ALL
                MATCH ()-[r:RELATIVE_IMPORTS]->() RETURN count(r) as count
                UNION ALL
                MATCH ()-[r:EXTERNAL_DEPENDENCIES]->() RETURN count(r) as count
                UNION ALL
                MATCH ()-[r:PACKAGE_DEPENDENCIES]->() RETURN count(r) as count
            """)
            total_deps = sum([record['count'] for record in result])
            stats['total_dependencies'] = total_deps
            
            # Dependencies by type
            direct_count = session.run("MATCH ()-[r:DIRECT_IMPORTS]->() RETURN count(r) as count").single()['count']
            relative_count = session.run("MATCH ()-[r:RELATIVE_IMPORTS]->() RETURN count(r) as count").single()['count']
            external_count = session.run("MATCH ()-[r:EXTERNAL_DEPENDENCIES]->() RETURN count(r) as count").single()['count']
            package_count = session.run("MATCH ()-[r:PACKAGE_DEPENDENCIES]->() RETURN count(r) as count").single()['count']
            
            stats['dependencies_by_type'] = {
                'direct_imports': direct_count,
                'relative_imports': relative_count,
                'external_dependencies': external_count,
                'package_dependencies': package_count
            }
            
            # Most dependent files (sum of all dependency types)
            result = session.run("""
                MATCH (f:File)-[r:DIRECT_IMPORTS]->() RETURN f.path as file, count(r) as count
                UNION ALL
                MATCH (f:File)-[r:RELATIVE_IMPORTS]->() RETURN f.path as file, count(r) as count
                UNION ALL
                MATCH (f:File)-[r:EXTERNAL_DEPENDENCIES]->() RETURN f.path as file, count(r) as count
                UNION ALL
                MATCH (f:File)-[r:PACKAGE_DEPENDENCIES]->() RETURN f.path as file, count(r) as count
            """)
            
            file_deps = {}
            for record in result:
                file_path = record['file']
                file_deps[file_path] = file_deps.get(file_path, 0) + record['count']
            
            # Sort by count and get top 10
            sorted_files = sorted(file_deps.items(), key=lambda x: x[1], reverse=True)[:10]
            stats['most_dependent_files'] = dict(sorted_files)
            
            # Most depended on files
            result = session.run("""
                MATCH ()-[r:DIRECT_IMPORTS]->(f:File) RETURN f.path as file, count(r) as count
                UNION ALL
                MATCH ()-[r:RELATIVE_IMPORTS]->(f:File) RETURN f.path as file, count(r) as count
            """)
            
            file_dependents = {}
            for record in result:
                file_path = record['file']
                file_dependents[file_path] = file_dependents.get(file_path, 0) + record['count']
            
            # Sort by count and get top 10
            sorted_dependents = sorted(file_dependents.items(), key=lambda x: x[1], reverse=True)[:10]
            stats['most_depended_on_files'] = dict(sorted_dependents)
            
            # Package dependencies by manager
            result = session.run("""
                MATCH ()-[r:PACKAGE_DEPENDENCIES]->(p:Package)
                RETURN r.package_manager as manager, count(r) as count
                ORDER BY count DESC
            """)
            stats['package_dependencies_by_manager'] = {record['manager']: record['count'] for record in result}
            
            return stats
    
    def export_graph_data(self, output_file: str = "dependency_graph.json"):
        """Export the dependency graph data to JSON format.
        
        Args:
            output_file: Output file path
        """
        import json
        
        with self.driver.session() as session:
            # Get all files
            result = session.run("MATCH (f:File) RETURN f")
            files = [dict(record['f']) for record in result]
            
            # Get all dependencies
            result = session.run("""
                MATCH (source:File)-[r:DEPENDS_ON]->(target:File)
                RETURN source.path as source, target.path as target, r.type as type
            """)
            dependencies = [dict(record) for record in result]
            
            # Get external modules
            result = session.run("MATCH (m:Module) RETURN m")
            modules = [dict(record['m']) for record in result]
            
            # Get external dependencies
            result = session.run("""
                MATCH (source:File)-[r:DEPENDS_ON]->(target:Module)
                RETURN source.path as source, target.name as target, r.type as type
            """)
            external_deps = [dict(record) for record in result]
            
            graph_data = {
                'files': files,
                'internal_dependencies': dependencies,
                'modules': modules,
                'external_dependencies': external_deps,
                'statistics': self.get_dependency_statistics()
            }
            
            with open(output_file, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            print(f"Graph data exported to {output_file}")
    
    def run_analysis_queries(self):
        """Run analysis queries and print results."""
        print("\n=== DEPENDENCY GRAPH ANALYSIS ===\n")
        
        with self.driver.session() as session:
            # 1. Circular dependencies
            print("1. Checking for circular dependencies...")
            result = session.run("""
                MATCH path = (f:File)-[:DEPENDS_ON*]->(f)
                RETURN f.path as file, length(path) as cycle_length
                ORDER BY cycle_length DESC
                LIMIT 5
            """)
            circular_deps = list(result)
            if circular_deps:
                print("Found circular dependencies:")
                for record in circular_deps:
                    print(f"  - {record['file']} (cycle length: {record['cycle_length']})")
            else:
                print("No circular dependencies found.")
            
            # 2. Files with most dependencies
            print("\n2. Files with most outgoing dependencies:")
            result = session.run("""
                MATCH (f:File)-[r:DEPENDS_ON]->()
                RETURN f.path as file, count(r) as dep_count
                ORDER BY dep_count DESC
                LIMIT 10
            """)
            for record in result:
                print(f"  - {record['file']}: {record['dep_count']} dependencies")
            
            # 3. Most depended on files
            print("\n3. Files with most incoming dependencies:")
            result = session.run("""
                MATCH ()-[r:DEPENDS_ON]->(f:File)
                RETURN f.path as file, count(r) as dep_count
                ORDER BY dep_count DESC
                LIMIT 10
            """)
            for record in result:
                print(f"  - {record['file']}: {record['dep_count']} dependents")
            
            # 4. External dependencies
            print("\n4. Most common external dependencies:")
            result = session.run("""
                MATCH ()-[r:DEPENDS_ON]->(m:Module)
                RETURN m.name as module, count(r) as dep_count
                ORDER BY dep_count DESC
                LIMIT 10
            """)
            for record in result:
                print(f"  - {record['module']}: {record['dep_count']} usages")
            
            # 5. Language distribution
            print("\n5. Files by programming language:")
            result = session.run("""
                MATCH (f:File)
                RETURN f.language as language, count(f) as count
                ORDER BY count DESC
            """)
            for record in result:
                print(f"  - {record['language']}: {record['count']} files") 