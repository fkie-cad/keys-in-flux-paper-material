def findkey(debugger, command, result, internal_dict):
    """
    Search for a key in process memory

    Usage:
        findkey <hex_string>                    # Normal search (skip regions >100MB)
        findkey --full <hex_string>             # Full search (all memory regions)
        findkey --verbose <hex_string>          # Normal search with debug output
        findkey --full --verbose <hex_string>   # Full search with debug output

    Searches the entire process memory for the specified hex pattern.
    """
    command = command.strip()

    # Parse flags
    full_search = False
    verbose = False

    while command.startswith('--'):
        if command.startswith('--full'):
            full_search = True
            command = command[6:].strip()
        elif command.startswith('--verbose'):
            verbose = True
            command = command[9:].strip()
        else:
            break

    hex_string = command

    if not hex_string:
        result.AppendMessage("[FINDKEY] Usage: findkey [--full] [--verbose] <hex_string>")
        result.AppendMessage("[FINDKEY] Example: findkey 1a2b3c4d5e6f70819293a4b5c6d7e8f9")
        result.AppendMessage("[FINDKEY] Example: findkey --full 1a2b3c4d5e6f70819293a4b5c6d7e8f9")
        result.AppendMessage("[FINDKEY] Example: findkey --verbose d77f8b958dc1fec97a70368199e04cb3")
        result.AppendMessage("[FINDKEY] Example: findkey --full --verbose <hex>")
        result.AppendMessage("[FINDKEY] ")
        result.AppendMessage("[FINDKEY] Flags:")
        result.AppendMessage("[FINDKEY]   --full      Search ALL memory regions (may be slow)")
        result.AppendMessage("[FINDKEY]   --verbose   Show debug output (regions searched, permissions, etc.)")
        return

    # Remove spaces and validate hex
    hex_string = hex_string.replace(" ", "").replace(":", "")

    try:
        search_bytes = bytes.fromhex(hex_string)
    except ValueError:
        result.AppendMessage(f"[FINDKEY] ✗ Invalid hex string: {hex_string}")
        return

    result.AppendMessage(f"[FINDKEY] Searching for key: {hex_string}")
    result.AppendMessage(f"[FINDKEY] Length: {len(search_bytes)} bytes")
    if full_search:
        result.AppendMessage(f"[FINDKEY] Mode: FULL (searching all memory regions)")
        if not verbose:
            result.AppendMessage(f"[FINDKEY] Warning: This may take 30-60 seconds...")
    if verbose:
        result.AppendMessage(f"[FINDKEY] Mode: VERBOSE (showing detailed debug output)")

    # Use the enhanced search function
    matches = _search_key_in_memory(search_bytes, ignore_size_limit=full_search, verbose=verbose)

    # Print results
    if matches:
        result.AppendMessage(f"[FINDKEY] ✓ Found {len(matches)} match(es):")
        for match in matches:
            addr_hex = f"0x{match['address']:x}"
            result.AppendMessage(f"[FINDKEY]   {addr_hex} ({match['module']}/{match['section']})")
    else:
        result.AppendMessage(f"[FINDKEY] ✗ Key not found in memory")

    result.AppendMessage(f"[FINDKEY] Search complete ({len(matches)} matches)")
