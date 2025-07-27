import os
import re
import base64
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path
import requests
from github import Github
from tqdm import tqdm
import config


class GitHubScanner:
    """Scans GitHub repositories for dependency information."""
    
    def __init__(self, token: str = None):
        """Initialize the GitHub scanner.
        
        Args:
            token: GitHub API token for authentication
        """
        self.token = token or config.GITHUB_TOKEN
        if self.token:
            print(f"🔑 Using GitHub token (length: {len(self.token)})")
            self.github = Github(self.token)
        else:
            print("⚠️  No GitHub token provided - using unauthenticated requests")
            self.github = None
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({'Authorization': f'token {self.token}'})
    
    def get_repo_contents(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get repository contents recursively.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: Path within repository (empty for root)
            
        Returns:
            List of file/directory information
        """
        print(f"🔍 Getting contents for path: {path or 'root'}")
        if self.github:
            return self._get_contents_via_api(owner, repo, path)
        else:
            return self._get_contents_via_web(owner, repo, path)
    
    def _get_contents_via_api(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get contents using GitHub API."""
        try:
            repository = self.github.get_repo(f"{owner}/{repo}")
            contents = repository.get_contents(path)
            
            files = []
            for content in contents:
                if content.type == "dir":
                    # Recursively get contents of subdirectories
                    sub_files = self._get_contents_via_api(owner, repo, content.path)
                    files.extend(sub_files)
                else:
                    # Check if file should be included
                    if self._should_include_file(content.path):
                        files.append({
                            'path': content.path,
                            'name': content.name,
                            'size': content.size,
                            'type': content.type,
                            'sha': content.sha,
                            'url': content.download_url
                        })
            return files
        except Exception as e:
            print(f"Error getting contents via API: {e}")
            return []
    
    def _get_contents_via_web(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get contents using GitHub web interface (fallback)."""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            response = self.session.get(url)
            response.raise_for_status()
            
            contents = response.json()
            if not isinstance(contents, list):
                contents = [contents]
            
            files = []
            for content in contents:
                if content['type'] == 'dir':
                    # Recursively get contents of subdirectories
                    sub_files = self._get_contents_via_web(owner, repo, content['path'])
                    files.extend(sub_files)
                else:
                    # Check if file should be included
                    if self._should_include_file(content['path']):
                        files.append({
                            'path': content['path'],
                            'name': content['name'],
                            'size': content['size'],
                            'type': content['type'],
                            'sha': content['sha'],
                            'url': content.get('download_url')
                        })
            return files
        except Exception as e:
            print(f"Error getting contents via web: {e}")
            return []
    
    def _should_include_file(self, file_path: str) -> bool:
        """Check if a file should be included in the scan.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be included, False otherwise
        """
        path_parts = Path(file_path).parts
        
        # Check if any directory in the path should be excluded
        for part in path_parts:
            if part in config.EXCLUDE_DIRS:
                return False
        
        # Check file extension
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in config.SUPPORTED_EXTENSIONS:
            return False
        
        # Check file name patterns
        file_name = Path(file_path).name
        for pattern in config.EXCLUDE_FILES:
            if self._matches_pattern(file_name, pattern):
                return False
        
        return True
    
    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches a pattern.
        
        Args:
            filename: Name of the file
            pattern: Pattern to match against
            
        Returns:
            True if filename matches pattern, False otherwise
        """
        if pattern.startswith('*.'):
            ext = pattern[1:]
            return filename.endswith(ext)
        return filename == pattern
    
    def get_file_content(self, file_info: Dict) -> Optional[str]:
        """Get the content of a file.
        
        Args:
            file_info: File information dictionary
            
        Returns:
            File content as string, or None if error
        """
        try:
            if file_info.get('url'):
                response = self.session.get(file_info['url'])
                response.raise_for_status()
                return response.text
            else:
                # Fallback: try to get content via API
                if self.github:
                    owner, repo = config.REPO_OWNER, config.REPO_NAME
                    repository = self.github.get_repo(f"{owner}/{repo}")
                    content = repository.get_contents(file_info['path'])
                    return content.decoded_content.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Error getting file content for {file_info['path']}: {e}")
            return None
    
    def scan_repository(self, owner: str, repo: str) -> List[Dict]:
        """Scan entire repository for files.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            List of file information dictionaries
        """
        print(f"Scanning repository: {owner}/{repo}")
        files = self.get_repo_contents(owner, repo)
        print("Scanning finished")
        # Filter and categorize files
        categorized_files = []
        for file_info in tqdm(files, desc="Processing files"):
            file_ext = Path(file_info['path']).suffix.lower()
            language = config.SUPPORTED_EXTENSIONS.get(file_ext, 'unknown')
            
            file_info['language'] = language
            file_info['extension'] = file_ext
            categorized_files.append(file_info)
        
        print(f"Found {len(categorized_files)} files to analyze")
        return categorized_files


class DependencyParser:
    """Parses dependencies from file contents."""
    
    def __init__(self):
        """Initialize the dependency parser."""
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        for language, patterns in config.IMPORT_PATTERNS.items():
            self.compiled_patterns[language] = [
                re.compile(pattern, re.MULTILINE | re.IGNORECASE)
                for pattern in patterns
            ]
    
    def parse_dependencies(self, file_path: str, content: str, language: str) -> List[Dict]:
        """Parse dependencies from file content.
        
        Args:
            file_path: Path to the file
            content: File content as string
            language: Programming language of the file
            
        Returns:
            List of dependency dictionaries
        """
        dependencies = []
        
        if language not in self.compiled_patterns:
            return dependencies
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in self.compiled_patterns[language]:
                matches = pattern.findall(line)
                for match in matches:
                    if isinstance(match, tuple):
                        # Handle patterns with multiple groups
                        for group in match:
                            if group:
                                dep = self._create_dependency(
                                    file_path, group, line.strip(), line_num, language
                                )
                                if dep:
                                    dependencies.append(dep)
                    else:
                        # Handle patterns with single group
                        if match:
                            dep = self._create_dependency(
                                file_path, match, line.strip(), line_num, language
                            )
                            if dep:
                                dependencies.append(dep)
        
        return dependencies
    
    def _create_dependency(self, file_path: str, import_name: str, 
                          import_statement: str, line_number: int, 
                          language: str) -> Optional[Dict]:
        """Create a dependency dictionary.
        
        Args:
            file_path: Path to the source file
            import_name: Name of the imported module/class
            import_statement: Full import statement
            line_number: Line number where import occurs
            language: Programming language
            
        Returns:
            Dependency dictionary or None if invalid
        """
        # Clean up import name
        import_name = import_name.strip()
        if not import_name or import_name.startswith('.'):
            return None
        
        # Determine dependency type
        dep_type = self._determine_dependency_type(import_name, language)
        
        return {
            'source_file': file_path,
            'import_name': import_name,
            'import_statement': import_statement,
            'line_number': line_number,
            'language': language,
            'type': dep_type
        }
    
    def _determine_dependency_type(self, import_name: str, language: str) -> str:
        """Determine the type of dependency.
        
        Args:
            import_name: Name of the imported module/class
            language: Programming language
            
        Returns:
            Dependency type ('internal', 'external', 'standard_library')
        """
        # Standard library modules for different languages
        std_libs = {
            'java': {
                'java.', 'javax.', 'sun.', 'com.sun.', 'org.w3c.', 'org.xml.'
            },
            'python': {
                'os', 'sys', 're', 'json', 'datetime', 'collections', 'itertools',
                'functools', 'pathlib', 'typing', 'abc', 'threading', 'asyncio',
                'logging', 'urllib', 'http', 'socket', 'subprocess', 'tempfile',
                'shutil', 'glob', 'fnmatch', 'pickle', 'copy', 'hashlib', 'base64'
            },
            'javascript': {
                'fs', 'path', 'http', 'https', 'url', 'querystring', 'crypto',
                'stream', 'events', 'util', 'buffer', 'os', 'child_process',
                'cluster', 'dgram', 'dns', 'domain', 'net', 'readline', 'repl',
                'string_decoder', 'tls', 'tty', 'v8', 'vm', 'zlib'
            },
            'typescript': {
                'fs', 'path', 'http', 'https', 'url', 'querystring', 'crypto',
                'stream', 'events', 'util', 'buffer', 'os', 'child_process',
                'cluster', 'dgram', 'dns', 'domain', 'net', 'readline', 'repl',
                'string_decoder', 'tls', 'tty', 'v8', 'vm', 'zlib'
            }
        }
        
        # Check if it's a standard library import
        if language in std_libs:
            if language == 'java':
                for std_prefix in std_libs[language]:
                    if import_name.startswith(std_prefix):
                        return 'standard_library'
            else:
                # For Python, JS, TS, check if it's a top-level standard library module
                first_part = import_name.split('.')[0]
                if first_part in std_libs[language]:
                    return 'standard_library'
        
        # Check if it's likely an internal dependency (Spring Framework specific)
        spring_patterns = [
            'org.springframework', 'spring', 'framework', 'core', 'context',
            'beans', 'web', 'data', 'security', 'boot', 'cloud'
        ]
        
        for pattern in spring_patterns:
            if pattern.lower() in import_name.lower():
                return 'internal'
        
        return 'external' 