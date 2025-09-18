import re
import sys

def parse_log_file(input_file, output_file):
    """
    Parse the drltrace log file and merge arg -1 blocks with their corresponding function calls.
    """
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    processed_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i].rstrip()
        
        # Check if this is a function call header line
        if re.match(r'~~\d+~~ \w+\.dll!\w+', line):
            function_header = line
            function_args = []
            i += 1
            
            # Collect all regular arguments for this function call (excluding arg -1)
            while i < len(lines) and lines[i].startswith('    arg ') and 'arg -1:' not in lines[i]:
                function_args.append(lines[i].rstrip())
                i += 1
            
            # Look for the nearest corresponding arg -1 block
            return_value = None
            j = i
            
            # Search forward for the same function call with arg -1
            while j < len(lines):
                if lines[j].rstrip() == function_header:
                    # Found the same function header, check if next line is arg -1
                    if j + 1 < len(lines) and 'arg -1:' in lines[j + 1]:
                        return_value = lines[j + 1].rstrip()
                        # Mark these lines to be skipped later
                        lines[j] = "# SKIP #"
                        lines[j + 1] = "# SKIP #"
                        break
                j += 1
            
            # Add the merged function call
            processed_lines.append(function_header)
            processed_lines.extend(function_args)
            if return_value:
                processed_lines.append(return_value)
                
        else:
            # Handle non-function lines, but skip marked lines
            if line.strip() and line != "# SKIP #":
                processed_lines.append(line)
            i += 1
    
    # Write the processed lines to output file
    with open(output_file, 'w') as f:
        for line in processed_lines:
            f.write(line + '\n')

def main():
    if len(sys.argv) != 3:
        print("Usage: python parse.py <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        parse_log_file(input_file, output_file)
        print(f"Successfully processed {input_file} -> {output_file}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()