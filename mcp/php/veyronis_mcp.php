<?php
/**
 * VEYRONIS PHP MCP (Model Context Protocol) Bridge
 * Enables PHP backends and AI agents to invoke Veyronis analysis tools via JSON-RPC.
 */

$binName = (PHP_OS_FAMILY === 'Windows') ? 'veyronis.exe' : 'veyronis';
if ($envBin = getenv('VEYRONIS_BIN')) {
    $binName = $envBin;
}

fwrite(STDERR, "[*] Starting VEYRONIS PHP MCP Bridge via {$binName}...\n");

$descriptors = [
    0 => ["pipe", "r"], // stdin
    1 => ["pipe", "w"], // stdout
    2 => STDERR          // stderr
];

$process = proc_open("{$binName} mcp", $descriptors, $pipes);

if (!is_resource($process)) {
    fwrite(STDERR, "[-] Failed to launch Veyronis process.\n");
    exit(1);
}

// Forward standard input to Veyronis and stream responses back
while (($line = fgets(STDIN)) !== false) {
    fwrite($pipes[0], $line);
    fflush($pipes[0]);
    $response = fgets($pipes[1]);
    if ($response !== false) {
        fwrite(STDOUT, $response);
        fflush(STDOUT);
    }
}

fclose($pipes[0]);
fclose($pipes[1]);
proc_close($process);
