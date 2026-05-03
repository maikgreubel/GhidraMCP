# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_REQUEST_TIMEOUT = 5

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER
# Initialize ghidra_request_timeout with default value
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)
    logger.debug(f"About to retrieve data from {url}")

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        
        logger.debug(f"About to post data to {url}")
        
        if isinstance(data, dict):
            # BSim queries might be a bit slower, using configurable timeout
            response = requests.post(url, data=data, timeout=ghidra_request_timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of methods to return (default: 100)
        
    Returns:
        List of function names
    """
    methods = safe_get("methods", {"offset": offset, "limit": limit})
    logger.debug(f"Response list for methods: {methods}")
    return methods

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of classes to return (default: 100)
        
    Returns:
        List of namespace/class names
    """
    classes = safe_get("classes", {"offset": offset, "limit": limit})
    logger.debug(f"Response list for classes: {classes}")
    return classes

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    
    Args:
        name: Name of the function to decompile
        
    Returns:
        Decompiled C code for the specified function, or an error message if decompilation fails
    """
    code = safe_post("decompile", name)
    logger.debug(f"Response for decompiling {code}")
    return code

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    
    Args:
        old_name: Current name of the function
        new_name: New name for the function
        
    Returns:
        Result of the renaming operation, or an error message if it fails
    """
    result = safe_post("renameFunction", {"oldName": old_name, "newName": new_name})
    logger.debug(f"Result for renaming {old_name} to {new_name} is {result}")
    return result

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    
    Args:
        address: Address of the data label in hex format (e.g., "0x1400010a0")
        new_name: New name for the data label
        
    Returns:
        Result of the renaming operation, or an error message if it fails
    """
    result = safe_post("renameData", {"address": address, "newName": new_name})
    logger.debug(f"Result for renaming label at {address} to {new_name} is {result}")
    return result

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of segments to return (default: 100)
        
    Returns:
        List of memory segments
    """
    segments = safe_get("segments", {"offset": offset, "limit": limit})
    logger.debug(f"Response list of segments: {segments}")
    return segments

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of imports to return (default: 100)
    
    Returns:
        List of imported symbols
    """
    imports = safe_get("imports", {"offset": offset, "limit": limit})
    logger.debug(f"Response list of imports: {imports}")
    return imports

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of exports to return (default: 100)

    Returns:
        List of exported functions/symbols
    """
    exports = safe_get("exports", {"offset": offset, "limit": limit})
    logger.debug(f"Response list of exports: {exports}")
    return exports

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of namespaces to return (default: 100)
        
    Returns:
        List of namespaces
    """
    namespaces = safe_get("namespaces", {"offset": offset, "limit": limit})
    logger.debug(f"Response list of namespaces: {namespaces}")
    return namespaces

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of data items to return (default: 100)
        
    Returns:
        List of data items
    """
    data_items = safe_get("data", {"offset": offset, "limit": limit})
    logger.debug(f"Response list of data items: {data_items}")
    return data_items

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    
    Args:
        query: Substring to search for in function names
        offset: Pagination offset (default: 0)
        limit: Maximum number of functions to return (default: 100)
        
    Returns:
        List of functions matching the search query
    """
    if not query:
        return ["Error: query string is required"]
    functions = safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})
    logger.debug(f"Response list of functions: {functions}")
    return functions

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    
    Args:
        function_name: Name of the function containing the variable
        old_name: Current name of the variable
        new_name: New name for the variable
        
    Returns:
        Result of the renaming operation, or an error message if it fails
    """
    result = safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })
    logger.debug(f"Result for renaming variable from {old_name} to {new_name} in function {function_name} is {result}")
    return result

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    
    Args:
        address: Address of the function in hex format (e.g., "0x1400010a0")
        
    Returns:
        Function prototype and decompiled C code for the function at the specified address, or an error message if retrieval fails
    """
    function = "\n".join(safe_get("get_function_by_address", {"address": address}))
    logger.debug(f"Function retrieved by its address {address} is {function}")
    return function

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    
    Returns:
        Currently selected address in hex format (e.g., "0x1400010a0"), or an error message if retrieval fails
    """
    current_address = "\n".join(safe_get("get_current_address"))
    logger.debug(f"Current address is {current_address}")
    return current_address

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    
    Returns:
        Currently selected function, or an error message if retrieval fails
    """
    current_function = "\n".join(safe_get("get_current_function"))
    logger.debug(f"Current function is {current_function}")
    return current_function

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    
    Returns:
        List of function names
    """
    functions = safe_get("list_functions")
    logger.debug(f"Response list of all functions: {functions}")
    return functions

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    
    Args:
        address: Address of the function in hex format (e.g., "0x1400010a0")
        
    Returns:
        Decompiled C code for the function at the specified address, or an error message if retrieval fails
    """
    function = "\n".join(safe_get("decompile_function", {"address": address}))
    logger.debug(f"Decompiled function at address {address} is {function}")
    return function

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    
    Args:
        address: Address of the function in hex format (e.g., "0x1400010a0")
        
    Returns:
        List of assembly code lines for the function at the specified address, or an error message if retrieval fails
    """    
    function = safe_get("disassemble_function", {"address": address})
    logger.debug(f"Disassembled function at address {address} is {function}")
    return function

@mcp.tool()
def disassemble_range(start_address: str, end_address: str) -> list:
    """
    Get assembly code for a given address range.
    
    Args:
        start_address: Start address of the range in hex format (e.g., "0x1400010a0")
        end_address: End address of the range in hex format (e.g., "0x1400011a0")
        
    Returns:
        List of assembly code lines for the specified address range, or an error message if retrieval fails
    """    
    code = safe_get("disassemble_range", {"start_address": start_address, "end_address": end_address})
    logger.debug(f"Disassembled code from address {start_address} to {end_address} is {code}")
    return code

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    
    Args:
        address: Address in hex format (e.g., "0x1400010a0")
        comment: Comment text to set at the specified address
    
    Returns:
        Result of the operation, or an error message if it fails
    """
    result = safe_post("set_decompiler_comment", {"address": address, "comment": comment})
    logger.debug(f"Result for setting decompiler comment '{comment}' at address {address} is {result}")
    return result

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    
    Args:
        address: Address in hex format (e.g., "0x1400010a0")
        comment: Comment text to set at the specified address
    
    Returns:
        Result of the operation, or an error message if it fails
    """
    result = safe_post("set_disassembly_comment", {"address": address, "comment": comment})
    logger.debug(f"Result for setting disassembly comment '{comment}' at address {address} is {result}")
    return result

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    
    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0")
        new_name: New name for the function
    
    Returns:
        Result of the operation, or an error message if it fails
    """
    result = safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})
    logger.debug(f"Result for renaming function at address {function_address} to {new_name} is {result}")
    return result

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    
    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0")
        prototype: New prototype for the function
    
    Returns:
        Result of the operation, or an error message if it fails
    """
    result = safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})
    logger.debug(f"Result for setting function prototype at address {function_address} to {prototype} is {result}")
    return result

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.

    Args:
        function_address: Address of the function in hex format (e.g., "0x1400010a0")
        variable_name: Name of the local variable
        new_type: New type for the local variable

    Returns:
        Result of the operation, or an error message if it fails
    """
    result = safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})
    logger.debug(f"Result for setting local variable {variable_name} at function address {function_address} to {new_type} is {result}")
    return result

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    xrefs_to = safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})
    logger.debug(f"Response list of xrefs to address {address} with offset {offset}: {xrefs_to}")
    return xrefs_to

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    xrefs_from = safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})
    logger.debug(f"Response list of xrefs to address {address} with offset {offset}: {xrefs_from}")
    return xrefs_from

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    function_xrefs = safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})
    logger.debug(f"Response list of function xrefs for {name} with offset {offset}: {function_xrefs}")
    return function_xrefs

@mcp.tool()
def search_strings(pattern:str) -> list:
    """
    Searches all strings for a matching pattern

    Args:
        pattern: A pattern to search for in the strings

    Returns:
        List of strings matching the pattern
    """
    params = {"pattern": pattern}
    strings = safe_get("search_strings", params)
    logger.debug(f"Response list of strings for pattern {pattern}: {strings}")
    return strings

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    strings = safe_get("strings", params)
    logger.debug(f"Response list of strings for offset {offset}: {strings}")
    return strings

@mcp.tool()
def bsim_select_database(database_path: str) -> str:
    """
    Select and connect to a BSim database for function similarity matching.

    Args:
        database_path: Path to BSim database file (e.g., "/path/to/database.bsim")
                      or URL (e.g., "postgresql://host:port/dbname")

    Returns:
        Connection status and database information
    """
    result = safe_post("bsim/select_database", {"database_path": database_path})
    logger.debug(f"Result for selecting database {database_path} is {result}")
    return result

@mcp.tool()
def bsim_query_function(
    function_address: str,
    max_matches: int = 10,
    similarity_threshold: float = 0.7,
    confidence_threshold: float = 0.0,
    max_similarity: float | None = None,
    max_confidence: float | None = None,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """
    Query a single function against the BSim database to find similar functions.

    Args:
        function_address: Address of the function to query (e.g., "0x401000")
        max_matches: Maximum number of matches to return (default: 10)
        similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
        confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
        max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
        max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of matching functions with similarity scores and metadata
    """
    data = {
        "function_address": function_address,
        "max_matches": str(max_matches),
        "similarity_threshold": str(similarity_threshold),
        "confidence_threshold": str(confidence_threshold),
        "offset": str(offset),
        "limit": str(limit),
    }
    
    if max_similarity is not None:
        data["max_similarity"] = str(max_similarity)
    if max_confidence is not None:
        data["max_confidence"] = str(max_confidence)
    
    result = safe_post("bsim/query_function", data)
    logger.debug(f"Result for querying bsim database for function address {function_address} is {result}")
    return result

@mcp.tool()
def bsim_query_all_functions(
    max_matches_per_function: int = 5,
    similarity_threshold: float = 0.7,
    confidence_threshold: float = 0.0,
    max_similarity: float | None = None,
    max_confidence: float | None = None,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """
    Query all functions in the current program against the BSim database.
    Returns an overview of matches for all functions.

    Args:
        max_matches_per_function: Max matches per function (default: 5)
        similarity_threshold: Minimum similarity score (inclusive, 0.0-1.0, default: 0.7)
        confidence_threshold: Minimum confidence score (inclusive, 0.0-1.0, default: 0.0)
        max_similarity: Maximum similarity score (exclusive, 0.0-1.0, default: unbounded)
        max_confidence: Maximum confidence score (exclusive, 0.0-1.0, default: unbounded)
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        Summary and detailed results for all matching functions
    """
    data = {
        "max_matches_per_function": str(max_matches_per_function),
        "similarity_threshold": str(similarity_threshold),
        "confidence_threshold": str(confidence_threshold),
        "offset": str(offset),
        "limit": str(limit),
    }
    
    if max_similarity is not None:
        data["max_similarity"] = str(max_similarity)
    if max_confidence is not None:
        data["max_confidence"] = str(max_confidence)
    
    functions = safe_post("bsim/query_all_functions", data)
    logger.debug(f"Result for all functions in bsim database with offset {offset} is {functions}")
    return functions

@mcp.tool()
def bsim_disconnect() -> str:
    """
    Disconnect from the current BSim database.

    Returns:
        Disconnection status message
    """
    result = safe_post("bsim/disconnect", {})
    logger.debug(f"Result for disconnecting from bsim database is {result}")
    return result

@mcp.tool()
def bsim_status() -> str:
    """
    Get the current BSim database connection status.

    Returns:
        Current connection status and database path if connected
    """
    status = "\n".join(safe_get("bsim/status"))
    logger.debug(f"Status of bsim database is {status}")
    return status

@mcp.tool()
def bsim_get_match_disassembly(
    executable_path: str,
    function_name: str,
    function_address: str,
) -> str:
    """
    Get the disassembly of a specific BSim match. This requires the matched 
    executable to be available in the Ghidra project.

    Args:
        executable_path: Path to the matched executable (from BSim match result)
        function_name: Name of the matched function
        function_address: Address of the matched function (e.g., "0x401000")

    Returns:
        Function prototype and assembly code for the matched function.
        Returns an error message if the program is not found in the project.
    """
    match_disassembly = safe_post("bsim/get_match_disassembly", {
        "executable_path": executable_path,
        "function_name": function_name,
        "function_address": function_address,
    })
    logger.debug(f"Result disassembly of address {function_address} for {function_name} in {executable_path}: {match_disassembly}")
    return match_disassembly

@mcp.tool()
def bsim_get_match_decompile(
    executable_path: str,
    function_name: str,
    function_address: str,
) -> str:
    """
    Get the decompilation of a specific BSim match. This requires the matched 
    executable to be available in the Ghidra project.

    Args:
        executable_path: Path to the matched executable (from BSim match result)
        function_name: Name of the matched function
        function_address: Address of the matched function (e.g., "0x401000")

    Returns:
        Function prototype and decompiled C code for the matched function.
        Returns an error message if the program is not found in the project.
    """
    match_decompile = safe_post("bsim/get_match_decompile", {
        "executable_path": executable_path,
        "function_name": function_name,
        "function_address": function_address,
    })
    logger.debug(f"Result decompile of address {function_address} for {function_name} in {executable_path}: {match_decompile}")
    return match_decompile

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--ghidra-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"MCP requests timeout, default: {DEFAULT_REQUEST_TIMEOUT}")
    parser.add_argument("--debug", type=bool, default=False,
                        help="Whether to enable debug logging during the process of bridging requests")
    parser.add_argument("--logfile", type=str, default=None,
                        help="Path of file where to put log entries into")
    
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    global ghidra_request_timeout
    if args.ghidra_timeout:
        ghidra_request_timeout = args.ghidra_timeout
        
    if args.transport == "sse":
        try:
            # Set up logging
            if args.debug:
                log_level = logging.DEBUG
            else:
                log_level = logging.INFO
            if not args.logfile == None:
                logging.basicConfig(level=log_level,filename=args.logfile)
            else:
                logging.basicConfig(level=log_level)
                                
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

