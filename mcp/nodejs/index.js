#!/usr/bin/env node
/**
 * VEYRONIS Node.js MCP (Model Context Protocol) Bridge
 * Connects any AI assistant (Claude Desktop, Cursor, Custom Agent) to Veyronis via stdio.
 */

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

// Find binary or cargo runner
const veyronisBin = process.env.VEYRONIS_BIN || (process.platform === 'win32' ? 'veyronis.exe' : 'veyronis');

console.error('[*] Starting VEYRONIS Node.js MCP Bridge...');

const child = spawn(veyronisBin, ['mcp'], {
    stdio: ['pipe', 'pipe', 'inherit']
});

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});

rl.on('line', (line) => {
    child.stdin.write(line + '\n');
});

child.stdout.on('data', (data) => {
    process.stdout.write(data);
});

child.on('exit', (code) => {
    console.error(`[-] Veyronis MCP process exited with code ${code}`);
    process.exit(code);
});
