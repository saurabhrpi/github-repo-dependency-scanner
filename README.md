# GitHub Repository Dependency Scanner

A comprehensive tool for scanning GitHub repositories and building dependency graphs using Neo4j. This tool can parse import statements across multiple programming languages and create detailed dependency visualizations.

## Features

- **Multi-language Support**: Parses dependencies from Java, Python, JavaScript, TypeScript, Kotlin, Groovy, XML, Gradle, YAML, and more
- **GitHub Integration**: Directly scans GitHub repositories using the GitHub API
- **Neo4j Graph Database**: Stores dependency relationships in a graph database for complex queries
- **Advanced Analysis**: Detects circular dependencies, identifies most dependent files, and analyzes dependency patterns
- **Visualization**: Generates charts and network graphs for dependency analysis
- **Export Capabilities**: Exports dependency data to JSON format for further analysis
- **Security Analysis**: Vulnerability scanning and upgrade path analysis with AI-powered recommendations
- **Agentic Graph Traversal**: Intelligent dependency chain analysis to find transitive vulnerabilities

## Prerequisites

- Python 3.8 or higher (Python 3.13 requires specific package versions)
- Neo4j Database (local or cloud instance)
- GitHub API token (optional, for higher rate limits)
- OpenAI API key (optional, for AI-powered upgrade analysis)

## Installation

### Windows Installation (Handling Compilation Issues)

If you're having compilation issues on Windows, try these approaches in order:

#### Option 1: Install Core Dependencies Only (Recommended)

```bash
# Install core packages (no compilation needed)
pip install neo4j==5.15.0 requests==2.31.0 beautifulsoup4==4.12.2 pygithub==2.1.1 python-dotenv==1.0.0 tqdm==4.66.1 openai==1.57.0 aiohttp==3.10.11 packaging==24.2

# Try lxml with pre-compiled wheels
pip install lxml==5.3.0 --only-binary=all
```

**What works with core dependencies:**
- ✅ Scanning GitHub repositories
- ✅ Parsing import statements
- ✅ Storing dependency graphs in Neo4j
- ✅ Running analysis queries
- ✅ Exporting data to JSON
- ✅ Vulnerability scanning and security analysis
- ✅ AI-powered upgrade recommendations
- ❌ Creating charts and network visualizations

#### Option 2: Full Installation with Pre-compiled Wheels

```bash
pip install -r requirements.txt --only-binary=all
```

#### Option 3: Use the Installation Script

```bash
python install_dependencies.py
```

#### Option 4: Manual Step-by-Step Installation

If the above options fail, install packages one by one:

```bash
# Step 1: Core packages
pip install neo4j==5.15.0
pip install requests==2.31.0
pip install beautifulsoup4==4.12.2
pip install pygithub==2.1.1
pip install python-dotenv==1.0.0
pip install tqdm==4.66.1
pip install openai==1.57.0
pip install aiohttp==3.10.11
pip install packaging==24.2

# Step 2: Try lxml with different approaches
pip install lxml==5.3.0 --only-binary=all
# If that fails, try:
pip install lxml>=5.0.0 --only-binary=all
# Or skip lxml entirely (beautifulsoup4 will still work)

# Step 3: Visualization packages (optional)
pip install networkx==3.2.1 --only-binary=all
pip install matplotlib==3.9.3 --only-binary=all
pip install seaborn==0.13.0 --only-binary=all
pip install pandas==2.2.3 --only-binary=all
```

### Troubleshooting

#### If you get compilation errors:

1. **Install Visual Studio Build Tools:**
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Install with "C++ build tools" workload

2. **Use Conda instead of pip:**
   ```bash
   conda install numpy pandas matplotlib seaborn lxml
   pip install neo4j requests beautifulsoup4 pygithub python-dotenv tqdm
   ```

3. **Use a different Python version:**
   - Try Python 3.9 or 3.10 (better wheel support)
   - Python 3.13 requires specific package versions (see requirements.txt)

4. **Skip problematic packages:**
   - The core functionality works without visualization packages
   - You can add them later when you have the build tools

#### If lxml fails:

The scanner will still work without lxml. BeautifulSoup4 can parse HTML/XML without it, just slightly slower.

### Set up Neo4j

- Install Neo4j Desktop or use Neo4j AuraDB (cloud)
- Create a new database
- Note down the connection details (URI, username, password)

### Configure environment variables (optional)

Create a `.env` file in the project root:
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
GITHUB_TOKEN=your_github_token
OPENAI_API_KEY=your_openai_api_key
```

## Usage

### Basic Usage

Scan the Spring Framework repository (default):

```bash
python main.py
```

### Advanced Usage

```bash
# Scan a different repository
python main.py --repo-owner microsoft --repo-name vscode

# Clear database before scanning
python main.py --clear-db

# Export graph data to JSON
python main.py --export-graph

# Run analysis queries after scanning
python main.py --analyze

# Limit number of files for testing
python main.py --max-files 100

# Combine multiple options
python main.py --clear-db --export-graph --analyze
```

### Visualization

Generate visualizations from existing graph data:

```bash
# Create all visualizations
python visualization.py

# Specify custom graph data file and output directory
python visualization.py --graph-data my_graph.json --output-dir my_visualizations
```

## Configuration

### Supported File Types

The scanner supports the following file extensions:

- **Java**: `.java`
- **Python**: `.py`
- **JavaScript**: `.js`, `.jsx`
- **TypeScript**: `.ts`, `.tsx`
- **Kotlin**: `.kt`
- **Groovy**: `.groovy`
- **XML**: `.xml`
- **Gradle**: `.gradle`
- **Properties**: `.properties`
- **YAML**: `.yml`, `.yaml`
- **Markdown**: `.md`
- **Text**: `.txt`

### Excluded Directories

The following directories are automatically excluded from scanning:

- `.git`, `node_modules`, `target`, `build`, `dist`
- `.gradle`, `out`, `bin`, `obj`, `__pycache__`
- `.pytest_cache`, `.idea`, `.vscode`, `coverage`
- `docs`, `documentation`

### Import Patterns

The tool uses regex patterns to detect imports in different languages:

- **Java**: `import`, `import static`, `package` statements
- **Python**: `import`, `from ... import` statements
- **JavaScript/TypeScript**: `import`, `require` statements
- **Kotlin/Groovy**: `import`, `package` statements
- **XML**: Namespace declarations
- **Gradle**: Dependency declarations

## Neo4j Database Schema

### Nodes

1. **File Node** (`:File`)
   - Properties: `path`, `name`, `extension`, `language`, `size`, `last_modified`

2. **Module Node** (`:Module`)
   - Properties: `name`, `type`

### Relationships

1. **DEPENDS_ON** (`:File`)-[:DEPENDS_ON]->(`:File`)
   - Properties: `type`, `import_statement`, `line_number`

2. **DEPENDS_ON** (`:File`)-[:DEPENDS_ON]->(`:Module`)
   - Properties: `type`, `import_statement`, `line_number`

## Analysis Queries

The tool provides several built-in analysis queries:

1. **Circular Dependencies**: Detects circular dependency chains
2. **Most Dependent Files**: Files with the most outgoing dependencies
3. **Most Depended On Files**: Files with the most incoming dependencies
4. **External Dependencies**: Most commonly used external modules
5. **Language Distribution**: File count by programming language

## Output Files

### JSON Export

The `--export-graph` option creates a JSON file with:

```json
{
  "files": [...],
  "internal_dependencies": [...],
  "modules": [...],
  "external_dependencies": [...],
  "statistics": {...}
}
```

### Visualizations

The visualization module creates:

- `language_distribution.png`: Pie chart of files by language
- `dependency_types.png`: Bar chart of dependency types
- `dependency_network.png`: Network graph of dependencies
- `top_dependencies.png`: Top most depended on files
- `summary_statistics.txt`: Text summary of statistics

## Examples

### Spring Framework Analysis

```bash
# Full analysis of Spring Framework
python main.py --clear-db --export-graph --analyze
```

This will:
1. Clear the Neo4j database
2. Scan the Spring Framework repository
3. Parse all Java, XML, and Gradle files
4. Create dependency relationships
5. Export data to JSON
6. Run analysis queries

### Custom Repository

```bash
# Analyze a different repository
python main.py --repo-owner facebook --repo-name react --clear-db --export-graph
```

### Visualization Only

```bash
# Create visualizations from existing data
python visualization.py --output-dir spring_analysis
```

## Troubleshooting

### Common Issues

1. **Neo4j Connection Error**:
   - Verify Neo4j is running
   - Check connection details in `.env` file
   - Ensure firewall allows connection

2. **GitHub API Rate Limits**:
   - Add GitHub token to `.env` file
   - Token provides higher rate limits

3. **Memory Issues**:
   - Use `--max-files` to limit processing
   - Increase system memory if needed

4. **Import Detection Issues**:
   - Check file extensions are supported
   - Verify import patterns in `config.py`

### Performance Tips

- Use `--max-files` for testing with large repositories
- Run Neo4j on SSD for better performance
- Increase Neo4j memory settings for large graphs
- Use GitHub token to avoid rate limiting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Spring Framework team for the example repository
- Neo4j team for the graph database
- GitHub for the API access
- Python community for the excellent libraries used

## Security Features

### Vulnerability Scanning

The tool includes advanced security analysis capabilities:

- **Vulnerability Scanner**: Checks packages against known security advisories
- **Upgrade Analyzer**: AI-powered recommendations for safe upgrade paths
- **Agentic Graph Traversal**: Intelligent analysis of transitive dependencies

### Running Security Analysis

```bash
# Run vulnerability scan on current graph
python vulnerability_scanner.py

# Analyze upgrade options with AI
python upgrade_analyzer.py

# Run comprehensive security tests
python test_system_vulnerability_analysis.py
```

## Dependencies

### Core Dependencies
- **neo4j**: Graph database driver
- **requests**: HTTP library for API calls
- **beautifulsoup4**: HTML/XML parsing
- **pygithub**: GitHub API wrapper
- **python-dotenv**: Environment variable management
- **tqdm**: Progress bars
- **openai**: AI-powered analysis
- **aiohttp**: Asynchronous HTTP client
- **packaging**: Version parsing and comparison

### Optional Dependencies (for visualization)
- **lxml**: Fast XML parsing
- **networkx**: Network analysis
- **matplotlib**: Plotting library
- **seaborn**: Statistical visualization
- **pandas**: Data analysis

### Python Version Compatibility

- Python 3.8-3.12: Use standard package versions
- Python 3.13: Requires specific versions (see requirements.txt):
  - pandas>=2.2.0
  - lxml>=5.0.0
  - matplotlib>=3.9.0

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review the configuration options
3. Open an issue on GitHub
4. Check the Neo4j documentation for database-specific questions
5. For security features, see the vulnerability scanning documentation 