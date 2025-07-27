#!/usr/bin/env python3
"""
GitHub Repository Dependency Scanner

This script scans GitHub repositories for dependency information and builds
dependency graphs using Neo4j. It supports multiple programming languages
including Java, Python, JavaScript, TypeScript, Kotlin, and more.

Usage:
    python main.py [options]

Options:
    --repo-owner OWNER    Repository owner (default: spring-projects)
    --repo-name NAME      Repository name (default: spring-framework)
    --clear-db           Clear database before scanning
    --export-graph       Export graph data to JSON
    --analyze            Run analysis queries after scanning
    --help               Show this help message
"""

import argparse
import sys
import time
import os
from typing import List, Dict
from tqdm import tqdm
from pathlib import Path

from github_scanner import GitHubScanner
from dependency_parser import DependencyParser
from neo4j_manager import Neo4jManager
import config


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for dependencies and build Neo4j graphs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--repo-owner',
        default=config.REPO_OWNER,
        help=f'Repository owner (default: {config.REPO_OWNER})'
    )
    
    parser.add_argument(
        '--repo-name',
        default=config.REPO_NAME,
        help=f'Repository name (default: {config.REPO_NAME})'
    )
    
    parser.add_argument(
        '--local-path',
        type=str,
        help='Path to local repository (use this instead of GitHub scanning)'
    )
    
    parser.add_argument(
        '--clear-db',
        action='store_true',
        help='Clear database before scanning'
    )
    
    parser.add_argument(
        '--export-graph',
        action='store_true',
        help='Export graph data to JSON file'
    )
    
    parser.add_argument(
        '--analyze',
        action='store_true',
        help='Run analysis queries after scanning'
    )
    
    parser.add_argument(
        '--max-files',
        type=int,
        default=None,
        help='Maximum number of files to process (for testing)'
    )
    
    return parser.parse_args()


class LocalFileScanner:
    """Scanner for local repository files."""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.supported_extensions = config.SUPPORTED_EXTENSIONS
        self.exclude_dirs = config.EXCLUDE_DIRS
        self.exclude_files = config.EXCLUDE_FILES
    
    def scan_repository(self, max_files: int = None) -> List[Dict]:
        """Scan local repository for files to analyze."""
        print(f"Scanning local repository: {self.repo_path}")
        
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.repo_path}")
        
        files = []
        scanned_count = 0
        
        # Walk through the repository directory
        for root, dirs, files_in_dir in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file_name in files_in_dir:
                # Skip excluded files
                if any(file_name.endswith(pattern.replace('*', '')) for pattern in self.exclude_files):
                    continue
                
                file_path = Path(root) / file_name
                extension = file_path.suffix.lower()
                
                # Check if file extension is supported
                if extension in self.supported_extensions:
                    # Get relative path from repository root
                    relative_path = str(file_path.relative_to(self.repo_path))
                    
                    # Get file info
                    try:
                        stat = file_path.stat()
                        file_info = {
                            'path': relative_path,
                            'name': file_name,
                            'extension': extension,
                            'language': self.supported_extensions[extension],
                            'size': stat.st_size,
                            'last_modified': stat.st_mtime
                        }
                        files.append(file_info)
                        scanned_count += 1
                        
                        # Check max files limit
                        if max_files and scanned_count >= max_files:
                            print(f"Reached maximum file limit: {max_files}")
                            break
                            
                    except (OSError, IOError) as e:
                        print(f"Error reading file {file_path}: {e}")
                        continue
            
            # Break if max files reached
            if max_files and scanned_count >= max_files:
                break
        
        print(f"Found {len(files)} files to analyze")
        return files
    
    def get_file_content(self, file_info: Dict) -> str:
        """Get content of a file from local repository."""
        try:
            file_path = self.repo_path / file_info['path']
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (OSError, IOError, UnicodeDecodeError) as e:
            print(f"Error reading file {file_info['path']}: {e}")
            return ""


def main():
    """Main function to orchestrate the dependency scanning process."""
    args = parse_arguments()
    
    print("=" * 60)
    if args.local_path:
        print("Local Repository Dependency Scanner")
        print("=" * 60)
        print(f"Local Repository: {args.local_path}")
    else:
        print("GitHub Repository Dependency Scanner")
        print("=" * 60)
        print(f"Repository: {args.repo_owner}/{args.repo_name}")
    print(f"Neo4j URI: {config.NEO4J_URI}")
    print("=" * 60)
    
    # Initialize components
    if args.local_path:
        scanner = LocalFileScanner(args.local_path)
    else:
        scanner = GitHubScanner()
    parser = DependencyParser()
    neo4j_manager = Neo4jManager()
    
    try:
        # Connect to Neo4j
        print("\n1. Connecting to Neo4j database...")
        neo4j_manager.connect()
        
        # Setup database
        print("\n2. Setting up database...")
        neo4j_manager.setup_database()
        
        # Clear database if requested
        if args.clear_db:
            print("\n3. Clearing database...")
            neo4j_manager.clear_database()
        
        # Scan repository
        if args.local_path:
            print(f"\n4. Scanning local repository...")
            files = scanner.scan_repository(max_files=args.max_files)
        else:
            print(f"\n4. Scanning repository {args.repo_owner}/{args.repo_name}...")
            
            if args.max_files:
                # For testing, scan only specific directories to avoid full repository traversal
                print(f"Using limited scan for testing (max files: {args.max_files})")
                test_paths = [
                    "spring-core/src/main/java/org/springframework/core",
                    "spring-context/src/main/java/org/springframework/context",
                    "spring-beans/src/main/java/org/springframework/beans"
                ]
                
                files = []
                for path in test_paths:
                    print(f"  Scanning: {path}")
                    try:
                        path_files = scanner.get_repo_contents(args.repo_owner, args.repo_name, path)
                        # Add language information to file_info objects
                        for file_info in path_files:
                            file_ext = Path(file_info['path']).suffix.lower()
                            file_info['language'] = config.SUPPORTED_EXTENSIONS.get(file_ext, 'unknown')
                            file_info['extension'] = file_ext
                        files.extend(path_files)
                        print(f"  Found {len(path_files)} files in {path}")
                        if len(files) >= args.max_files:
                            break
                    except Exception as e:
                        print(f"  Error scanning {path}: {e}")
                
                # Limit to requested number of files
                files = files[:args.max_files]
                print(f"Limited to {len(files)} files for testing")
            else:
                # Full repository scan
                files = scanner.scan_repository(args.repo_owner, args.repo_name)
        
        if not files:
            print("No files found to analyze.")
            return
        
        # Create file nodes
        print(f"\n5. Creating file nodes in Neo4j...")
        successful_files = 0
        for file_info in tqdm(files, desc="Creating file nodes"):
            if neo4j_manager.create_file_node(file_info):
                successful_files += 1
        
        print(f"Created {successful_files} file nodes out of {len(files)} files")
        
        # Parse dependencies
        print(f"\n6. Parsing dependencies...")
        all_dependencies = []
        
        for file_info in tqdm(files, desc="Parsing dependencies"):
            content = scanner.get_file_content(file_info)
            if content:
                # Parse source code dependencies
                file_dependencies = parser.parse_file_dependencies(
                    file_info['path'],
                    content,
                    file_info['language']
                )
                all_dependencies.extend(file_dependencies)
                
                # Parse package dependencies from configuration files
                if file_info['name'] in config.PACKAGE_DEPENDENCY_FILES.get(file_info['language'], []):
                    package_dependencies = parser.parse_package_dependencies(
                        file_info['path'],
                        content
                    )
                    all_dependencies.extend(package_dependencies)
        
        print(f"Found {len(all_dependencies)} dependencies")
        
        # Get dependency statistics
        dep_stats = parser.get_dependency_statistics(all_dependencies)
        print(f"  Direct imports: {dep_stats['direct_imports']}")
        print(f"  Relative imports: {dep_stats['relative_imports']}")
        print(f"  Package dependencies: {dep_stats['package_dependencies']}")
        print(f"  External dependencies: {dep_stats['external_dependencies']}")
        
        if dep_stats['by_package_manager']:
            print("  By package manager:")
            for manager, count in dep_stats['by_package_manager'].items():
                print(f"    {manager}: {count}")
        
        # Create dependency relationships
        print(f"\n7. Creating dependency relationships in Neo4j...")
        successful_deps = 0
        
        for dependency in tqdm(all_dependencies, desc="Creating dependencies"):
            if neo4j_manager.create_dependency_relationship(dependency):
                successful_deps += 1
        
        print(f"Created {successful_deps} dependency relationships out of {len(all_dependencies)}")
        
        # Get statistics
        print(f"\n8. Generating statistics...")
        stats = neo4j_manager.get_dependency_statistics()
        
        print("\n" + "=" * 40)
        print("SCANNING COMPLETED")
        print("=" * 40)
        print(f"Total files processed: {stats.get('total_files', 0)}")
        print(f"Total dependencies: {stats.get('total_dependencies', 0)}")
        
        if 'files_by_language' in stats:
            print("\nFiles by language:")
            for lang, count in stats['files_by_language'].items():
                print(f"  {lang}: {count}")
        
        # Show dependency statistics by category
        print("\nDependencies by category:")
        print(f"  Direct imports: {dep_stats['direct_imports']}")
        print(f"  Relative imports: {dep_stats['relative_imports']}")
        print(f"  Package dependencies: {dep_stats['package_dependencies']}")
        print(f"  External dependencies: {dep_stats['external_dependencies']}")
        
        if dep_stats['by_package_manager']:
            print("\nPackage dependencies by manager:")
            for manager, count in dep_stats['by_package_manager'].items():
                print(f"  {manager}: {count}")
        
        # Export graph data if requested
        if args.export_graph:
            print(f"\n9. Exporting graph data...")
            neo4j_manager.export_graph_data("dependency_graph.json")
        
        # Run analysis if requested
        if args.analyze:
            print(f"\n10. Running analysis queries...")
            neo4j_manager.run_analysis_queries()
        
        print("\n" + "=" * 40)
        print("PROCESS COMPLETED SUCCESSFULLY")
        print("=" * 40)
        
    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError during processing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Disconnect from Neo4j
        neo4j_manager.disconnect()


if __name__ == "__main__":
    main() 