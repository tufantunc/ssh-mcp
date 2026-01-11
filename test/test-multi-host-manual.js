#!/usr/bin/env node

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

async function testMultiHost() {
  console.log('🚀 Starting multi host tests...\n');

  // genrate MCP client
  const transport = new StdioClientTransport({
    command: 'node',
    args: [
      'build/index.js',
      '--host=vm1.example.com',
      '--port=2222',
      '--user=root',
      '--key=C:\\Users\\user\\.ssh\\id_ed25519'
    ]
  });

  const client = new Client({
    name: 'multi-host-test-client',
    version: '1.0.0'
  }, {
    capabilities: {}
  });

  try {
    await client.connect(transport);
    console.log('✅ MCP Client bağlandı\n');

    // Test 1: Default host (vm1.example.com:2222)
    console.log('📍 Test 1: Default host (vm1.example.com:2222)');
    try {
      const result1 = await client.callTool({
        name: 'exec',
        arguments: {
          command: 'hostname && echo "=== VM1 Test ===" && uname -a',
          description: 'Test vm1.example.com'
        }
      });
      console.log('✅ vm1.example.com yanıt:');
      console.log(result1.content[0].text);
    } catch (err) {
      console.error('❌ vm1.example.com error:', err.message);
    }

    // Test 2: second host (vm2.example.com:2222)
    console.log('\n📍 Test 2: second host (vm2.example.com:2222)');
    try {
      const result2 = await client.callTool({
        name: 'exec',
        arguments: {
          command: 'hostname && echo "=== VM2 Test ===" && uname -a',
          description: 'Test vm2.example.com',
          host: 'vm2.example.com:2222'
        }
      });
      console.log('✅ vm2.example.com response:');
      console.log(result2.content[0].text);
    } catch (err) {
      console.error('❌ vm2.example.com error:', err.message);
    }

    // Test 3: check connection list with list-hosts
    console.log('\n📍 Test 3: list active connections');
    try {
      const result3 = await client.callTool({
        name: 'list-hosts',
        arguments: {}
      });
      console.log('✅ Active connections:');
      console.log(result3.content[0].text);
    } catch (err) {
      console.error('❌ list-hosts hatası:', err.message);
    }

    // Test 4: another command to vm1 (connection reuse)
    console.log('\n📍 Test 4: vm1.example.com test again (connection reuse)');
    try {
      const result4 = await client.callTool({
        name: 'exec',
        arguments: {
          command: 'uptime',
          description: 'Check vm1 uptime'
        }
      });
      console.log('✅ vm1.example.com uptime:');
      console.log(result4.content[0].text);
    } catch (err) {
      console.error('❌ vm1.example.com uptime error:', err.message);
    }

    // Test 5: another command to vm2 (connection reuse)
    console.log('\n📍 Test 5: vm2.example.com test again (connection reuse)');
    try {
      const result5 = await client.callTool({
        name: 'exec',
        arguments: {
          command: 'uptime',
          description: 'Check vm2 uptime',
          host: 'vm2.example.com:2222'
        }
      });
      console.log('✅ vm2.example.com uptime:');
      console.log(result5.content[0].text);
    } catch (err) {
      console.error('❌ vm2.example.com uptime error:', err.message);
    }

    // Test 6: Parallel commands
    console.log('\n📍 Test 6: parallel commands to both servers');
    try {
      const startTime = Date.now();
      const [result6a, result6b] = await Promise.all([
        client.callTool({
          name: 'exec',
          arguments: {
            command: 'sleep 2 && echo "VM1 done"',
            description: 'Parallel test on vm1'
          }
        }),
        client.callTool({
          name: 'exec',
          arguments: {
            command: 'sleep 2 && echo "VM2 done"',
            description: 'Parallel test on vm2',
            host: 'vm2.example.com:2222'
          }
        })
      ]);
      const duration = Date.now() - startTime;
      console.log(`✅ Parallel commands completed (${duration}ms - ~2 seconds or so)`);
      console.log('vm1 yanıt:', result6a.content[0].text.trim());
      console.log('vm2 yanıt:', result6b.content[0].text.trim());
    } catch (err) {
      console.error('❌ Paralel test error:', err.message);
    }

    // Test 7: Final list-hosts check
    console.log('\n📍 Test 7: Final connection check');
    try {
      const result7 = await client.callTool({
        name: 'list-hosts',
        arguments: {}
      });
      console.log('✅ Final connection status:');
      console.log(result7.content[0].text);
    } catch (err) {
      console.error('❌ Final list-hosts error:', err.message);
    }

    console.log('\n🎉 All tests completed!');

  } catch (error) {
    console.error('❌ Fatal error:', error);
  } finally {
    await client.close();
    console.log('\n👋 MCP Client connection closed');
  }
}

testMultiHost().catch(console.error);
