#!/usr/bin/env python3
"""
Query Neo4j database to show dependency information.

This script queries the Neo4j database to show:
- All nodes and their types
- Dependencies by category (direct_imports, relative_imports, external_dependencies)
- Dependencies by type (direct_import, relative_import, package_dependency, external_dependency)
- Package dependencies by manager
"""

import argparse
import sys
from neo4j_manager import Neo4jManager
import config


def get_comprehensive_stats(neo4j_manager):
    """Get comprehensive statistics about all nodes and dependencies."""
    print("=" * 80)
    print("COMPREHENSIVE DATABASE STATISTICS")
    print("=" * 80)
    
    with neo4j_manager.driver.session() as session:
        # 1. Node Statistics
        print("\n1. NODE STATISTICS")
        print("-" * 50)
        
        # Count all nodes by type
        result = session.run("""
            MATCH (n)
            RETURN labels(n) as labels, count(n) as count
            ORDER BY count DESC
        """)
        
        total_nodes = 0
        print("Nodes by type:")
        for record in result:
            labels = record['labels']
            count = record['count']
            total_nodes += count
            print(f"  {labels}: {count}")
        
        print(f"\nTotal nodes: {total_nodes}")
        
        # 2. File Statistics
        print("\n2. FILE STATISTICS")
        print("-" * 50)
        
        # Files by language
        result = session.run("""
            MATCH (f:File)
            RETURN f.language as language, count(f) as count
            ORDER BY count DESC
        """)
        
        print("Files by language:")
        for record in result:
            language = record['language'] or 'unknown'
            count = record['count']
            print(f"  {language}: {count}")
        
        # Files by extension
        result = session.run("""
            MATCH (f:File)
            RETURN f.extension as extension, count(f) as count
            ORDER BY count DESC
            LIMIT 10
        """)
        
        print("\nFiles by extension (top 10):")
        for record in result:
            extension = record['extension'] or 'no_extension'
            count = record['count']
            print(f"  {extension}: {count}")
        
        # 3. Relationship Statistics
        print("\n3. RELATIONSHIP STATISTICS")
        print("-" * 50)
        
        # Count all relationships by type
        result = session.run("""
            MATCH ()-[r]->()
            RETURN type(r) as relationship_type, count(r) as count
            ORDER BY count DESC
        """)
        
        total_relationships = 0
        print("Relationships by type:")
        for record in result:
            rel_type = record['relationship_type']
            count = record['count']
            total_relationships += count
            print(f"  {rel_type}: {count}")
        
        print(f"\nTotal relationships: {total_relationships}")
        
        # 4. Dependency Statistics
        print("\n4. DEPENDENCY STATISTICS")
        print("-" * 50)
        
        # Direct imports
        direct_count = session.run("MATCH ()-[r:DIRECT_IMPORTS]->() RETURN count(r) as count").single()['count']
        print(f"Direct imports: {direct_count}")
        
        # Relative imports
        relative_count = session.run("MATCH ()-[r:RELATIVE_IMPORTS]->() RETURN count(r) as count").single()['count']
        print(f"Relative imports: {relative_count}")
        
        # External dependencies
        external_count = session.run("MATCH ()-[r:EXTERNAL_DEPENDENCIES]->() RETURN count(r) as count").single()['count']
        print(f"External dependencies: {external_count}")
        
        # Package dependencies
        package_count = session.run("MATCH ()-[r:PACKAGE_DEPENDENCIES]->() RETURN count(r) as count").single()['count']
        print(f"Package dependencies: {package_count}")
        
        total_deps = direct_count + relative_count + external_count + package_count
        print(f"\nTotal dependencies: {total_deps}")
        
        # 5. Module Statistics
        print("\n5. MODULE STATISTICS")
        print("-" * 50)
        
        # External modules by type
        result = session.run("""
            MATCH (m:Module)
            RETURN m.type as type, count(m) as count
            ORDER BY count DESC
        """)
        
        print("External modules by type:")
        for record in result:
            module_type = record['type'] or 'unknown'
            count = record['count']
            print(f"  {module_type}: {count}")
        
        # 6. Package Statistics
        print("\n6. PACKAGE STATISTICS")
        print("-" * 50)
        
        # Package dependencies by manager
        result = session.run("""
            MATCH ()-[r:PACKAGE_DEPENDENCIES]->(p:Package)
            RETURN r.package_manager as manager, count(r) as count
            ORDER BY count DESC
        """)
        
        print("Package dependencies by manager:")
        for record in result:
            manager = record['manager'] or 'unknown'
            count = record['count']
            print(f"  {manager}: {count}")
        
        # 7. Most Connected Files
        print("\n7. MOST CONNECTED FILES")
        print("-" * 50)
        
        # Files with most outgoing dependencies
        result = session.run("""
            MATCH (f:File)-[r]->()
            RETURN f.path as file, count(r) as outgoing_count
            ORDER BY outgoing_count DESC
            LIMIT 10
        """)
        
        print("Files with most outgoing dependencies (top 10):")
        for record in result:
            file_path = record['file']
            count = record['outgoing_count']
            print(f"  {file_path}: {count} dependencies")
        
        # Files with most incoming dependencies
        result = session.run("""
            MATCH ()-[r]->(f:File)
            RETURN f.path as file, count(r) as incoming_count
            ORDER BY incoming_count DESC
            LIMIT 10
        """)
        
        print("\nFiles with most incoming dependencies (top 10):")
        for record in result:
            file_path = record['file']
            count = record['incoming_count']
            print(f"  {file_path}: {count} dependents")
        
        # 8. Graph Density
        print("\n8. GRAPH DENSITY")
        print("-" * 50)
        
        if total_nodes > 1:
            density = total_relationships / (total_nodes * (total_nodes - 1))
            print(f"Graph density: {density:.6f}")
        else:
            print("Graph density: N/A (insufficient nodes)")
        
        print(f"Average dependencies per file: {total_deps / max(1, total_nodes):.2f}")
        
        print("\n" + "=" * 80)
        print("COMPREHENSIVE STATISTICS COMPLETED")
        print("=" * 80)


def get_all_files(neo4j_manager):
    """Get a complete list of all files in the database."""
    print("=" * 80)
    print("COMPLETE LIST OF ALL FILES")
    print("=" * 80)
    
    with neo4j_manager.driver.session() as session:
        # Get all files with their details
        result = session.run("""
            MATCH (f:File)
            RETURN f.path as path, f.language as language, f.extension as extension, f.size as size
            ORDER BY f.path
        """)
        
        file_count = 0
        print(f"{'Path':<80} {'Language':<12} {'Extension':<10} {'Size':<8}")
        print("-" * 120)
        
        for record in result:
            path = record['path']
            language = record['language'] or 'unknown'
            extension = record['extension'] or 'none'
            size = record['size'] or 0
            
            # Truncate long paths for display
            display_path = path if len(path) <= 78 else path[:75] + "..."
            
            print(f"{display_path:<80} {language:<12} {extension:<10} {size:<8}")
            file_count += 1
        
        print("-" * 120)
        print(f"Total files: {file_count}")
        print("=" * 80)


def get_all_dependencies(neo4j_manager):
    """Get detailed information about all dependencies."""
    print("=" * 80)
    print("COMPLETE LIST OF ALL DEPENDENCIES")
    print("=" * 80)
    
    with neo4j_manager.driver.session() as session:
        # 1. Direct Imports
        print("\n1. DIRECT IMPORTS")
        print("-" * 80)
        result = session.run("""
            MATCH (source:File)-[r:DIRECT_IMPORTS]->(target)
            RETURN source.path as source, target.path as target, r.import_statement as import_stmt, r.line_number as line
            ORDER BY source.path, target.path
        """)
        
        direct_count = 0
        for record in result:
            source = record['source']
            target = record['target']
            import_stmt = record['import_stmt']
            line = record['line']
            
            print(f"Source: {source}")
            print(f"Target: {target}")
            print(f"Import: {import_stmt}")
            print(f"Line:   {line}")
            print("-" * 80)
            direct_count += 1
        
        print(f"Total direct imports: {direct_count}")
        
        # 2. Relative Imports
        print("\n2. RELATIVE IMPORTS")
        print("-" * 80)
        result = session.run("""
            MATCH (source:File)-[r:RELATIVE_IMPORTS]->(target:File)
            RETURN source.path as source, target.path as target, r.import_statement as import_stmt, r.line_number as line
            ORDER BY source.path, target.path
        """)
        
        relative_count = 0
        for record in result:
            source = record['source']
            target = record['target']
            import_stmt = record['import_stmt']
            line = record['line']
            
            print(f"Source: {source}")
            print(f"Target: {target}")
            print(f"Import: {import_stmt}")
            print(f"Line:   {line}")
            print("-" * 80)
            relative_count += 1
        
        print(f"Total relative imports: {relative_count}")
        
        # 3. External Dependencies
        print("\n3. EXTERNAL DEPENDENCIES")
        print("-" * 80)
        result = session.run("""
            MATCH (source:File)-[r:EXTERNAL_DEPENDENCIES]->(target:Module)
            RETURN source.path as source, target.name as module, target.type as type, r.import_statement as import_stmt, r.line_number as line
            ORDER BY source.path, target.name
        """)
        
        external_count = 0
        for record in result:
            source = record['source']
            module = record['module']
            module_type = record['type']
            import_stmt = record['import_stmt']
            line = record['line']
            
            print(f"Source: {source}")
            print(f"Module: {module}")
            print(f"Type:   {module_type}")
            print(f"Import: {import_stmt}")
            print(f"Line:   {line}")
            print("-" * 80)
            external_count += 1
        
        print(f"Total external dependencies: {external_count}")
        
        # 4. Package Dependencies
        print("\n4. PACKAGE DEPENDENCIES")
        print("-" * 80)
        result = session.run("""
            MATCH (source:File)-[r:PACKAGE_DEPENDENCIES]->(target:Package)
            RETURN source.path as source, target.name as package, target.version as version, r.package_manager as manager
            ORDER BY source.path, target.name
        """)
        
        package_count = 0
        for record in result:
            source = record['source']
            package = record['package']
            version = record['version'] or 'unknown'
            manager = record['manager'] or 'unknown'
            
            print(f"Source:  {source}")
            print(f"Package: {package}")
            print(f"Version: {version}")
            print(f"Manager: {manager}")
            print("-" * 80)
            package_count += 1
        
        print(f"Total package dependencies: {package_count}")
        
        # Summary
        total_deps = direct_count + relative_count + external_count + package_count
        print(f"\n" + "=" * 80)
        print("DEPENDENCY SUMMARY")
        print("=" * 80)
        print(f"Direct imports:      {direct_count}")
        print(f"Relative imports:    {relative_count}")
        print(f"External dependencies: {external_count}")
        print(f"Package dependencies: {package_count}")
        print(f"Total dependencies:  {total_deps}")
        print("=" * 80)


def main():
    """Query and display Neo4j database information."""
    parser = argparse.ArgumentParser(description='Query Neo4j database for dependency information')
    parser.add_argument('--comprehensive', '-c', action='store_true', 
                       help='Show comprehensive statistics')
    parser.add_argument('--basic', '-b', action='store_true', 
                       help='Show basic statistics (default)')
    parser.add_argument('--files', '-f', action='store_true',
                       help='Show complete list of all files')
    parser.add_argument('--dependencies', '-d', action='store_true',
                       help='Show detailed list of all dependencies')
    
    args = parser.parse_args()
    
    # Default to basic if no specific mode is chosen
    if not any([args.comprehensive, args.basic, args.files, args.dependencies]):
        args.basic = True
    
    print("=" * 60)
    print("Neo4j Database Query Tool")
    print("=" * 60)
    
    neo4j_manager = Neo4jManager()
    
    try:
        # Connect to Neo4j
        print("Connecting to Neo4j...")
        neo4j_manager.connect()
        
        if args.comprehensive:
            get_comprehensive_stats(neo4j_manager)
        elif args.files:
            get_all_files(neo4j_manager)
        elif args.dependencies:
            get_all_dependencies(neo4j_manager)
        elif args.basic:
            # Original basic statistics
            print("\n1. Basic Database Statistics:")
            print("-" * 40)
            
            with neo4j_manager.driver.session() as session:
                # Count all nodes by type
                result = session.run("""
                    MATCH (n)
                    RETURN labels(n) as labels, count(n) as count
                    ORDER BY count DESC
                """)
                
                print("Nodes by type:")
                for record in result:
                    labels = record['labels']
                    count = record['count']
                    print(f"  {labels}: {count}")
            
            # Get dependency statistics
            print("\n2. Dependency Statistics:")
            print("-" * 40)
            
            stats = neo4j_manager.get_dependency_statistics()
            
            print(f"Total files: {stats.get('total_files', 0)}")
            print(f"Total dependencies: {stats.get('total_dependencies', 0)}")
            
            if 'dependencies_by_type' in stats:
                print("\nDependencies by type:")
                for dep_type, count in stats['dependencies_by_type'].items():
                    print(f"  {dep_type}: {count}")
            
            if 'package_dependencies_by_manager' in stats:
                print("\nPackage dependencies by manager:")
                for manager, count in stats['package_dependencies_by_manager'].items():
                    print(f"  {manager}: {count}")
            
            # Show sample relationships
            print("\n3. Sample Dependencies:")
            print("-" * 40)
            
            with neo4j_manager.driver.session() as session:
                # Direct imports
                result = session.run("""
                    MATCH (source:File)-[r:DIRECT_IMPORTS]->(target)
                    RETURN source.path as source, target.path as target, r.import_statement as import_stmt
                    LIMIT 5
                """)
                
                print("Direct imports (sample):")
                for record in result:
                    print(f"  {record['source']} -> {record['target']}")
                    print(f"    Import: {record['import_stmt']}")
                
                # Relative imports
                result = session.run("""
                    MATCH (source:File)-[r:RELATIVE_IMPORTS]->(target)
                    RETURN source.path as source, target.path as target, r.import_statement as import_stmt
                    LIMIT 5
                """)
                
                print("\nRelative imports (sample):")
                for record in result:
                    print(f"  {record['source']} -> {record['target']}")
                    print(f"    Import: {record['import_stmt']}")
                
                # Package dependencies
                result = session.run("""
                    MATCH (source:File)-[r:PACKAGE_DEPENDENCIES]->(target:Package)
                    RETURN source.path as source, target.name as package, target.version as version, r.package_manager as manager
                    LIMIT 5
                """)
                
                print("\nPackage dependencies (sample):")
                for record in result:
                    print(f"  {record['source']} -> {record['package']} {record['version']} ({record['manager']})")
                
                # External dependencies
                result = session.run("""
                    MATCH (source:File)-[r:EXTERNAL_DEPENDENCIES]->(target:Module)
                    RETURN source.path as source, target.name as module, target.type as type
                    LIMIT 5
                """)
                
                print("\nExternal dependencies (sample):")
                for record in result:
                    print(f"  {record['source']} -> {record['module']} ({record['type']})")
            
            # Show most dependent files
            print("\n4. Most Dependent Files:")
            print("-" * 40)
            
            if 'most_dependent_files' in stats:
                for file_path, count in list(stats['most_dependent_files'].items())[:5]:
                    print(f"  {file_path}: {count} dependencies")
            
            # Show most depended on files
            print("\n5. Most Depended On Files:")
            print("-" * 40)
            
            if 'most_depended_on_files' in stats:
                for file_path, count in list(stats['most_depended_on_files'].items())[:5]:
                    print(f"  {file_path}: {count} dependents")
            
            print("\n" + "=" * 60)
            print("Query completed successfully!")
            print("=" * 60)
        
    except Exception as e:
        print(f"Error querying database: {e}")
        import traceback
        traceback.print_exc()
    finally:
        neo4j_manager.disconnect()


if __name__ == "__main__":
    main() 