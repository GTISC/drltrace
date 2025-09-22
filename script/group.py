import re
import argparse
import sys
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional

class FunctionCall:
    def __init__(self, block_id: int, process_id: str, dll_name: str, function_name: str, 
                 args: List[Tuple[str, str]], line_number: int):
        self.block_id = block_id
        self.process_id = process_id
        self.dll_name = dll_name
        self.function_name = function_name
        self.args = args  # List of (arg_position, value) tuples
        self.line_number = line_number
    
    def __repr__(self):
        return f"Block {self.block_id}: {self.dll_name}!{self.function_name}"

class DependencyGrouper:
    def __init__(self):
        self.function_calls: List[FunctionCall] = []
        self.value_to_blocks: Dict[str, Set[int]] = defaultdict(set)
        self.dependency_graph: Dict[int, Set[int]] = defaultdict(set)
        self.groups: List[List[int]] = []
    
    def parse_log_file(self, filename: str):
        """Parse the drltrace log file and extract function calls"""
        block_id = 0
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
            sys.exit(1)
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Match function call pattern: ~~PID~~ DLL!FUNCTION
            func_match = re.match(r'~~(\d+)~~ (.+?)!(.+)', line)
            if func_match:
                block_id += 1
                process_id = func_match.group(1)
                dll_name = func_match.group(2)
                function_name = func_match.group(3)
                
                # Parse arguments from following lines
                args = []
                i += 1
                while i < len(lines) and lines[i].strip().startswith('arg'):
                    arg_line = lines[i].strip()
                    arg_match = re.match(r'arg (-?\d+): (.+)', arg_line)
                    if arg_match:
                        arg_pos = arg_match.group(1)
                        arg_value = arg_match.group(2)
                        # Extract only the first hex value (the pointer address)
                        hex_match = re.search(r'0x[0-9a-fA-F]+', arg_value)
                        if hex_match:
                            hex_val = hex_match.group(0)
                            if hex_val != '0x0000000000000000':  # Ignore null pointers
                                args.append((arg_pos, hex_val))
                    i += 1
                
                func_call = FunctionCall(block_id, process_id, dll_name, function_name, args, i)
                self.function_calls.append(func_call)
                
                # Index arguments by value
                for arg_pos, value in args:
                    self.value_to_blocks[value].add(block_id)
            else:
                i += 1
    
    def build_dependency_graph(self):
        """Build dependency graph based on shared argument values"""
        for value, blocks in self.value_to_blocks.items():
            if len(blocks) > 1:
                block_list = sorted(blocks)
                # Create dependencies: later blocks depend on earlier blocks with same value
                for i in range(len(block_list)):
                    for j in range(i + 1, len(block_list)):
                        earlier_block = block_list[i]
                        later_block = block_list[j]
                        self.dependency_graph[later_block].add(earlier_block)
    
    def find_connected_components(self):
        """Find groups of connected function calls"""
        visited = set()
        
        def iterative_dfs(start_block: int, current_group: Set[int]):
            stack = [start_block]
            
            while stack:
                block_id = stack.pop()
                
                if block_id in visited:
                    continue
                
                visited.add(block_id)
                current_group.add(block_id)
                
                # Add dependencies (blocks this one depends on)
                for dep in self.dependency_graph[block_id]:
                    if dep not in visited:
                        stack.append(dep)
                
                # Add dependents (blocks that depend on this one)
                for other_block, deps in self.dependency_graph.items():
                    if block_id in deps and other_block not in visited:
                        stack.append(other_block)
        
        # Process all blocks
        for func_call in self.function_calls:
            if func_call.block_id not in visited:
                group = set()
                iterative_dfs(func_call.block_id, group)
                if group:
                    self.groups.append(sorted(group))
    
    def print_results(self, show_details: bool = True, max_groups: Optional[int] = None):
        """Print the grouped function calls with dependencies"""
        print("=== FUNCTION CALL DEPENDENCY ANALYSIS ===\n")
        
        print(f"Total function calls: {len(self.function_calls)}")
        print(f"Total dependency groups: {len(self.groups)}\n")
        
        groups_to_show = self.groups[:max_groups] if max_groups else self.groups
        
        for group_num, group in enumerate(groups_to_show, 1):
            print(f"GROUP {group_num} ({len(group)} blocks):")
            print("-" * 50)
            
            # Print blocks in chronological order
            for block_id in group:
                func_call = self.function_calls[block_id - 1]  # block_id is 1-indexed
                print(f"  Block {block_id}: {func_call.dll_name}!{func_call.function_name}")
                
                if show_details:
                    # Show dependencies within this group
                    deps_in_group = [dep for dep in self.dependency_graph[block_id] if dep in group]
                    if deps_in_group:
                        print(f"    Dependencies: {sorted(deps_in_group)}")
                    
                    # Show shared values that create dependencies
                    shared_values = []
                    for arg_pos, value in func_call.args:
                        if len(self.value_to_blocks[value]) > 1:
                            other_blocks = [b for b in self.value_to_blocks[value] if b != block_id and b in group]
                            if other_blocks:
                                shared_values.append(f"{value} (shared with blocks {sorted(other_blocks)})")
                    
                    if shared_values:
                        print(f"    Shared values: {shared_values[:3]}...")  # Show first 3 to avoid clutter
                
                print()
            
            print()
        
        if max_groups and len(self.groups) > max_groups:
            print(f"... and {len(self.groups) - max_groups} more groups. Use --all to show all groups.")
    
    def save_grouped_results(self, output_filename: str, show_details: bool = True):
        """Save results to a file"""
        try:
            with open(output_filename, 'w') as f:
                f.write("=== FUNCTION CALL DEPENDENCY ANALYSIS ===\n\n")
                f.write(f"Total function calls: {len(self.function_calls)}\n")
                f.write(f"Total dependency groups: {len(self.groups)}\n\n")
                
                for group_num, group in enumerate(self.groups, 1):
                    f.write(f"GROUP {group_num} ({len(group)} blocks):\n")
                    f.write("-" * 50 + "\n")
                    
                    for block_id in group:
                        func_call = self.function_calls[block_id - 1]
                        f.write(f"  Block {block_id}: {func_call.dll_name}!{func_call.function_name}\n")
                        
                        if show_details:
                            # Dependencies
                            deps_in_group = [dep for dep in self.dependency_graph[block_id] if dep in group]
                            if deps_in_group:
                                f.write(f"    Dependencies: {sorted(deps_in_group)}\n")
                            
                            # Shared values
                            shared_values = []
                            for arg_pos, value in func_call.args:
                                if len(self.value_to_blocks[value]) > 1:
                                    other_blocks = [b for b in self.value_to_blocks[value] if b != block_id and b in group]
                                    if other_blocks:
                                        shared_values.append(f"{value} (blocks {sorted(other_blocks)})")
                            
                            if shared_values:
                                f.write(f"    Shared values: {', '.join(shared_values[:5])}\n")
                        
                        f.write("\n")
                    
                    f.write("\n")
            print(f"Results saved to '{output_filename}'")
        except Exception as e:
            print(f"Error writing to file '{output_filename}': {e}")
            sys.exit(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Analyze drltrace log files and group function calls by dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s result.log                           # Basic analysis with default output
  %(prog)s -i trace.log -o analysis.txt        # Specify input and output files
  %(prog)s --input log.txt --no-details        # Hide detailed dependency information
  %(prog)s result.log --max-groups 5           # Show only first 5 groups
  %(prog)s result.log --quiet --output out.txt # Save to file without console output
        """)
    
    parser.add_argument('input', nargs='?', default='result.log',
                      help='Input drltrace log file (default: result.log)')
    
    parser.add_argument('-i', '--input', dest='input_file',
                      help='Input drltrace log file (alternative to positional argument)')
    
    parser.add_argument('-o', '--output', dest='output_file',
                      help='Output file for results (default: display on console)')
    
    parser.add_argument('--no-details', action='store_true',
                      help='Hide detailed dependency and shared value information')
    
    parser.add_argument('--max-groups', type=int, metavar='N',
                      help='Maximum number of groups to display (default: show all)')
    
    parser.add_argument('-q', '--quiet', action='store_true',
                      help='Suppress console output (useful when saving to file)')
    
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    
    return parser.parse_args()

def main():
    """Main function to run the dependency analysis"""
    args = parse_arguments()
    
    # Determine input file
    input_file = args.input_file if args.input_file else args.input
    
    if not args.quiet:
        print(f"Analyzing file: {input_file}")
    
    # Initialize grouper
    grouper = DependencyGrouper()
    
    # Parse the log file
    if not args.quiet:
        print("Parsing log file...")
    grouper.parse_log_file(input_file)
    
    if len(grouper.function_calls) == 0:
        print("No function calls found in the log file.")
        sys.exit(1)
    
    # Build dependency graph
    if not args.quiet:
        print("Building dependency graph...")
    grouper.build_dependency_graph()
    
    # Find connected components (groups)
    if not args.quiet:
        print("Finding dependency groups...")
    grouper.find_connected_components()
    
    # Display results on console (unless quiet mode)
    if not args.quiet:
        show_details = not args.no_details
        grouper.print_results(show_details=show_details, max_groups=args.max_groups)
    
    # Save to file if specified
    if args.output_file:
        if not args.quiet:
            print(f"Saving results to '{args.output_file}'...")
        show_details = not args.no_details
        grouper.save_grouped_results(args.output_file, show_details=show_details)
    
    if not args.quiet:
        print("Analysis complete!")

if __name__ == "__main__":
    main()