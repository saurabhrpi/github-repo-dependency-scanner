"""
Agentic Graph Traversal Agent with timeout handling and performance improvements.
"""

from typing import List, Dict, Tuple, Any, Optional, Set
from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from vulnerability_scanner import get_vulnerable_packages
import json
import re
from dataclasses import dataclass, field
from heapq import heappush, heappop
import openai
import os
from datetime import datetime
from enum import Enum
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time
import pickle


class TraversalDecision(Enum):
    """Types of decisions made during traversal."""
    EXPLORED = "explored"
    SKIPPED_LOW_PRIORITY = "skipped_low_priority"
    SKIPPED_VISITED = "skipped_visited"
    SKIPPED_DEPTH_LIMIT = "skipped_depth_limit"
    SKIPPED_NODE_LIMIT = "skipped_node_limit"
    SKIPPED_TIMEOUT = "skipped_timeout"
    SKIPPED_LLM_ERROR = "skipped_llm_error"


@dataclass
class VulnerableNode:
    """Enhanced node with reasoning and risk assessment."""
    package_name: str
    version: str
    file_path: str
    import_line: str
    import_line_number: int
    code_context: str
    advisories: List[Dict[str, Any]]
    priority_score: float = 0.0
    
    # Enhanced fields for tracking decisions
    llm_reasoning: str = ""
    risk_category: str = "UNKNOWN"
    traversal_depth: int = 0
    parent_file: Optional[str] = None
    decision: TraversalDecision = TraversalDecision.EXPLORED
    decision_rationale: str = ""
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __lt__(self, other):
        # For heap - higher priority scores come first
        return self.priority_score > other.priority_score


@dataclass
class TraversalState:
    """Maintains state for resumable traversal."""
    priority_queue: List[VulnerableNode]
    visited: Set[Tuple[str, str]]
    analyzed_nodes: List[VulnerableNode]
    traversal_history: List[Dict]
    skipped_nodes: List[Dict]
    step_counter: int
    start_time: float
    checkpoint_file: str = "traversal_checkpoint.pkl"
    
    def save_checkpoint(self):
        """Save current state to disk for resumption."""
        state_dict = {
            'priority_queue': self.priority_queue,
            'visited': self.visited,
            'analyzed_nodes': self.analyzed_nodes,
            'traversal_history': self.traversal_history,
            'skipped_nodes': self.skipped_nodes,
            'step_counter': self.step_counter,
            'start_time': self.start_time
        }
        with open(self.checkpoint_file, 'wb') as f:
            pickle.dump(state_dict, f)
        print(f"Checkpoint saved at step {self.step_counter}")
    
    @classmethod
    def load_checkpoint(cls, checkpoint_file: str = "traversal_checkpoint.pkl"):
        """Load state from disk."""
        try:
            with open(checkpoint_file, 'rb') as f:
                state_dict = pickle.load(f)
            
            state = cls(
                priority_queue=state_dict['priority_queue'],
                visited=state_dict['visited'],
                analyzed_nodes=state_dict['analyzed_nodes'],
                traversal_history=state_dict['traversal_history'],
                skipped_nodes=state_dict['skipped_nodes'],
                step_counter=state_dict['step_counter'],
                start_time=state_dict['start_time'],
                checkpoint_file=checkpoint_file
            )
            print(f"Resumed from checkpoint at step {state.step_counter}")
            return state
        except FileNotFoundError:
            return None
        except ModuleNotFoundError as e:
            print(f"Warning: Checkpoint file contains outdated module references: {e}")
            print("Starting fresh traversal...")
            return None


class AgenticGraphTraversalAgent:
    """Optimized agent with timeout handling and performance improvements."""
    
    def __init__(self, neo4j_uri: str = NEO4J_URI, neo4j_user: str = NEO4J_USER, 
                 neo4j_password: str = NEO4J_PASSWORD, openai_api_key: Optional[str] = None,
                 llm_timeout: int = 30, use_cache: bool = True, batch_size: int = 5):
        """
        Initialize the agent with optimizations.
        
        Args:
            neo4j_uri: Neo4j database URI
            neo4j_user: Database username
            neo4j_password: Database password
            openai_api_key: OpenAI API key for LLM analysis
            llm_timeout: Timeout for LLM calls in seconds
            use_cache: Whether to cache LLM responses
            batch_size: Number of neighbors to analyze in one LLM call
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        # Initialize OpenAI client
        api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        if api_key:
            self.llm_client = openai.OpenAI(api_key=api_key)
        else:
            raise ValueError("OpenAI API key is required.")
        
        # Optimization settings
        self.llm_timeout = llm_timeout
        self.use_cache = use_cache
        self.batch_size = batch_size
        
        # Cache for LLM responses
        self.llm_cache = {}
        self.cache_file = "llm_cache.json"
        if use_cache:
            self._load_cache()
        
        # Executor for timeout handling
        self.executor = ThreadPoolExecutor(max_workers=3)
    
    def _load_cache(self):
        """Load LLM response cache from disk."""
        try:
            with open(self.cache_file, 'r') as f:
                self.llm_cache = json.load(f)
            print(f"Loaded {len(self.llm_cache)} cached LLM responses")
        except FileNotFoundError:
            self.llm_cache = {}
    
    def _save_cache(self):
        """Save LLM response cache to disk."""
        if self.use_cache:
            with open(self.cache_file, 'w') as f:
                json.dump(self.llm_cache, f)
    
    def close(self):
        """Close database connection and save cache."""
        self.driver.close()
        self.executor.shutdown()
        self._save_cache()
    
    def _get_cache_key(self, current_node: VulnerableNode, neighbors: List[Dict]) -> str:
        """Generate cache key for LLM request."""
        # Create a deterministic key based on the context
        key_parts = [
            current_node.package_name,
            current_node.version,
            current_node.file_path,
            str(len(neighbors)),
            # Include first few file paths to differentiate contexts
            '|'.join(sorted([n['file_path'] for n in neighbors[:3]]))
        ]
        return '::'.join(key_parts)
    
    def build_prompt_and_prioritize_with_timeout(self, current_node: VulnerableNode, 
                                                neighbors: List[Dict[str, Any]], 
                                                advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build prompt and get priorities with timeout handling.
        """
        # Check cache first
        if self.use_cache:
            cache_key = self._get_cache_key(current_node, neighbors)
            if cache_key in self.llm_cache:
                print(f"  Using cached LLM response for {current_node.file_path}")
                return self.llm_cache[cache_key]
        
        try:
            # Run LLM call with timeout
            future = self.executor.submit(
                self._llm_analyze_neighbors,
                current_node, neighbors, advisories
            )
            result = future.result(timeout=self.llm_timeout)
            
            # Cache the result
            if self.use_cache:
                self.llm_cache[cache_key] = result
                
            return result
            
        except TimeoutError:
            raise RuntimeError(f"LLM timeout after {self.llm_timeout} seconds for {current_node.file_path}")
        except Exception as e:
            raise RuntimeError(f"LLM error for {current_node.file_path}: {e}")
    
    def _llm_analyze_neighbors(self, current_node: VulnerableNode, 
                              neighbors: List[Dict[str, Any]], 
                              advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Actual LLM analysis - runs in separate thread."""
        prompt = self._build_analysis_prompt(current_node, neighbors, advisories)
        
        response = self.llm_client.chat.completions.create(
            model="gpt-3.5-turbo",  # Use faster model
            messages=[
                {"role": "system", "content": "You are a security expert. Be concise."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1000  # Reduced for faster response
        )
        
        analysis = response.choices[0].message.content
        return self._parse_llm_analysis(neighbors, analysis, advisories)
    
    
    def _build_analysis_prompt(self, current_node: VulnerableNode, 
                              neighbors: List[Dict[str, Any]], 
                              advisories: List[Dict[str, Any]]) -> str:
        """Build a more concise prompt for faster LLM response."""
        highest_advisory = max(advisories, key=lambda x: x.get("cvss_score", 0))
        
        prompt = f"""Analyze security impact of {current_node.package_name} {current_node.version} (CVSS: {highest_advisory.get('cvss_score', 0)}).

Analyzing from: {current_node.file_path}

Rate each file (0-10) based on security risk. Consider:
- Authentication/security components = 8-10
- User-facing APIs/routes = 6-8  
- Data processing = 4-6
- Tests/examples = 0-3

FILES:
"""
        
        # Batch neighbors for efficiency
        for i, neighbor in enumerate(neighbors[:self.batch_size]):
            prompt += f"\n{i+1}. {neighbor['file_path']}"
            prompt += f"\n   Import: {neighbor['import_statement'][:100]}..."
        
        prompt += """

Respond with JSON only:
[{"index": 1, "priority_score": 8, "reasoning": "Auth component", "risk_category": "HIGH", "should_explore": true}]
"""
        
        return prompt
    
    def _parse_llm_analysis(self, neighbors: List[Dict[str, Any]], 
                           llm_response: str, 
                           advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse LLM response with error handling."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\[.*\]', llm_response, re.DOTALL)
            if json_match:
                analysis_results = json.loads(json_match.group())
            else:
                raise ValueError("Failed to parse LLM response - no valid JSON found")
            
            max_cvss = max((adv.get("cvss_score", 0) for adv in advisories), default=5.0)
            
            analyzed_neighbors = []
            for result in analysis_results:
                idx = result["index"] - 1
                if 0 <= idx < len(neighbors):
                    neighbor = neighbors[idx].copy()
                    
                    # Combine scores
                    context_score = result["priority_score"] / 10.0
                    cvss_normalized = max_cvss / 10.0
                    combined_score = (0.6 * context_score + 0.4 * cvss_normalized) * 10
                    
                    neighbor.update({
                        "priority_score": combined_score,
                        "llm_reasoning": result.get("reasoning", ""),
                        "risk_category": result.get("risk_category", "UNKNOWN"),
                        "should_explore": result.get("should_explore", False),
                        "exploitation_scenario": result.get("exploitation_scenario", "")
                    })
                    
                    analyzed_neighbors.append(neighbor)
            
            # Skip any neighbors not analyzed by LLM
            # (This ensures we only use LLM-based decisions)
            
            analyzed_neighbors.sort(key=lambda x: x["priority_score"], reverse=True)
            return analyzed_neighbors
            
        except Exception as e:
            raise RuntimeError(f"Failed to parse LLM response: {e}")
    
    def traverse_vulnerability_graph(self, max_depth: int = 3, max_nodes: int = 100,
                                   max_time_minutes: int = 10, 
                                   resume_from_checkpoint: bool = True) -> List[VulnerableNode]:
        """
        Optimized traversal with time limits and checkpointing.
        
        Args:
            max_depth: Maximum traversal depth
            max_nodes: Maximum number of nodes to analyze
            max_time_minutes: Maximum time to run in minutes
            resume_from_checkpoint: Whether to resume from saved state
            
        Returns:
            List of analyzed vulnerable nodes
        """
        print("Starting optimized vulnerability graph traversal...")
        
        # Try to resume from checkpoint
        state = None
        if resume_from_checkpoint:
            state = TraversalState.load_checkpoint()
        
        if state is None:
            # Initialize new traversal
            vulnerable_packages = get_vulnerable_packages()
            
            state = TraversalState(
                priority_queue=[],
                visited=set(),
                analyzed_nodes=[],
                traversal_history=[],
                skipped_nodes=[],
                step_counter=0,
                start_time=time.time()
            )
            
            # Initialize queue with vulnerable packages
            print("Initializing with vulnerable packages...")
            for package_name, version, advisories in vulnerable_packages:
                neighbors = self.list_neighbors(package_name, version)
                
                if neighbors:
                    # Use LLM for initial scoring
                    initial_scored = self.build_prompt_and_prioritize_with_timeout(
                        VulnerableNode(
                            package_name=package_name,
                            version=version,
                            file_path="<root>",
                            import_line="",
                            import_line_number=0,
                            code_context="",
                            advisories=advisories,
                            traversal_depth=0
                        ),
                        neighbors[:10],
                        advisories
                    )
                    
                    for neighbor in initial_scored[:5]:
                        node = VulnerableNode(
                            package_name=package_name,
                            version=version,
                            file_path=neighbor["file_path"],
                            import_line=neighbor["import_statement"],
                            import_line_number=neighbor["line_number"],
                            code_context=neighbor["code_context"],
                            advisories=advisories,
                            priority_score=neighbor["priority_score"],
                            llm_reasoning=neighbor.get("llm_reasoning", ""),
                            risk_category=neighbor.get("risk_category", "UNKNOWN"),
                            traversal_depth=1
                        )
                        heappush(state.priority_queue, node)
        
        # Time limit
        max_time_seconds = max_time_minutes * 60
        checkpoint_interval = 10  # Save checkpoint every 10 nodes
        
        # Traverse graph
        while state.priority_queue and len(state.analyzed_nodes) < max_nodes:
            # Check time limit
            elapsed = time.time() - state.start_time
            if elapsed > max_time_seconds:
                print(f"\nTime limit reached ({max_time_minutes} minutes)")
                break
            
            current_node = heappop(state.priority_queue)
            
            # Skip if already visited
            node_key = (current_node.package_name, current_node.file_path)
            if node_key in state.visited:
                continue
            
            # Check depth limit
            if current_node.traversal_depth > max_depth:
                current_node.decision = TraversalDecision.SKIPPED_DEPTH_LIMIT
                state.skipped_nodes.append({"node": current_node, "reason": "depth_limit"})
                continue
            
            state.visited.add(node_key)
            state.analyzed_nodes.append(current_node)
            state.step_counter += 1
            
            print(f"[Step {state.step_counter}] Analyzing: {current_node.file_path} "
                  f"(priority: {current_node.priority_score:.2f}, risk: {current_node.risk_category})")
            
            # Save checkpoint periodically
            if state.step_counter % checkpoint_interval == 0:
                state.save_checkpoint()
            
            # Find next level neighbors (with timeout protection)
            try:
                with self.driver.session() as session:
                    query = """
                    MATCH (f1:File)-[r:DIRECT_IMPORTS|RELATIVE_IMPORTS]->(f2:File)
                    WHERE f2.path = $file_path
                    RETURN f1.path as importing_file, 
                           f1.code as code,
                           r.import_statement as import_statement,
                           r.line_number as line_number
                    LIMIT 20
                    """
                    
                    result = session.run(query, file_path=current_node.file_path)
                    
                    next_neighbors = []
                    for record in result:
                        next_neighbors.append({
                            "file_path": record["importing_file"],
                            "import_statement": record["import_statement"],
                            "line_number": record["line_number"],
                            "code_context": self._extract_code_context(
                                record["code"] or "", 
                                record["line_number"]
                            )
                        })
                
                # Analyze neighbors with timeout protection
                if next_neighbors:
                    analyzed_neighbors = self.build_prompt_and_prioritize_with_timeout(
                        current_node, next_neighbors, current_node.advisories
                    )
                    
                    # Add high-priority neighbors to queue
                    for neighbor in analyzed_neighbors:
                        if neighbor.get("should_explore", False) and neighbor["priority_score"] >= 5:
                            next_node = VulnerableNode(
                                package_name=current_node.package_name,
                                version=current_node.version,
                                file_path=neighbor["file_path"],
                                import_line=neighbor["import_statement"],
                                import_line_number=neighbor["line_number"],
                                code_context=neighbor["code_context"],
                                advisories=current_node.advisories,
                                priority_score=neighbor["priority_score"],
                                llm_reasoning=neighbor.get("llm_reasoning", ""),
                                risk_category=neighbor.get("risk_category", "UNKNOWN"),
                                traversal_depth=current_node.traversal_depth + 1,
                                parent_file=current_node.file_path
                            )
                            heappush(state.priority_queue, next_node)
                
            except Exception as e:
                print(f"  Error processing neighbors: {e}")
                continue
        
        # Final checkpoint
        state.save_checkpoint()
        
        elapsed_minutes = (time.time() - state.start_time) / 60
        print(f"\nTraversal complete in {elapsed_minutes:.1f} minutes")
        print(f"Analyzed {len(state.analyzed_nodes)} nodes, skipped {len(state.skipped_nodes)} nodes")
        
        return state.analyzed_nodes
    
    def list_neighbors(self, package_name: str, version: str, 
                      import_site_snippet: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all files that import the given package."""
        with self.driver.session() as session:
            query = """
            MATCH (f:File)-[r:EXTERNAL_DEPENDENCIES]->(m:Module)
            WHERE m.name = $package_name
            RETURN f.path as file_path, 
                   f.code as code,
                   r.import_statement as import_statement,
                   r.line_number as line_number
            LIMIT 50
            """
            
            result = session.run(query, package_name=package_name)
            
            neighbors = []
            for record in result:
                neighbors.append({
                    "file_path": record["file_path"],
                    "import_statement": record["import_statement"],
                    "line_number": record["line_number"],
                    "code_context": self._extract_code_context(
                        record["code"] or "", 
                        record["line_number"]
                    )
                })
            
            return neighbors
    
    def _extract_code_context(self, code: str, line_number: int, window: int = 5) -> str:
        """Extract smaller code context for efficiency."""
        if not code:
            return ""
        
        lines = code.split('\n')
        start = max(0, line_number - 1 - window)
        end = min(len(lines), line_number + window)
        
        context_lines = []
        for i in range(start, end):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            context_lines.append(f"{line_num:4d}{prefix}{lines[i][:100]}")  # Truncate long lines
        
        return '\n'.join(context_lines)


if __name__ == "__main__":
    # Example usage with optimizations
    agent = AgenticGraphTraversalAgent(
        llm_timeout=30,  # 30 second timeout per LLM call
        use_cache=True,  # Cache LLM responses
        batch_size=5     # Analyze 5 files at a time
    )
    
    try:
        # Run with time limit
        analyzed_nodes = agent.traverse_vulnerability_graph(
            max_depth=3,
            max_nodes=50,
            max_time_minutes=5,  # Stop after 5 minutes
            resume_from_checkpoint=True  # Resume if interrupted
        )
        
        print(f"\nAnalyzed {len(analyzed_nodes)} vulnerable nodes")
        
    finally:
        agent.close()