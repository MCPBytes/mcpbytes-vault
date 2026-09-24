"""End-to-end stdio checks. Uses disposable local OS-generated test material; never prints it."""
import base64, json, os, queue, subprocess, sys, tempfile, threading
from pathlib import Path

binary=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='mcpbytes-vault-test-') as folder:
    root=Path(folder)
    for name in ('state','keys'):
        (root/name).mkdir(mode=0o700)
    config={'state_dir':str(root/'state'),'store':{'backend':'private_file','directory':str(root/'keys')},
            'label_prefix':'smoke-','mode':'local_only'}
    path=root/'config.json'
    path.write_text(json.dumps(config))
    process=subprocess.Popen([str(binary),'--config',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    lines=queue.Queue()
    transcript=[]
    def reader():
        for line in process.stdout:
            transcript.append(line)
            lines.put(line)
    threading.Thread(target=reader,daemon=True).start()
    def send(body):
        process.stdin.write(json.dumps(body)+'\n')
        process.stdin.flush()
    def call(identifier,method,params):
        send({'jsonrpc':'2.0','id':identifier,'method':method,'params':params})
        while True:
            message=json.loads(lines.get(timeout=15))
            if message.get('id')==identifier: return message
    try:
        response=call(1,'initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'vault-test','version':'1'}})
        assert 'result' in response
        send({'jsonrpc':'2.0','method':'notifications/initialized'})
        tools={t['name']:t for t in call(2,'tools/list',{})['result']['tools']}
        assert sorted(tools)==['get_random_bytes','list_secrets']
        # The owner's configuration is stated in the tool itself.
        generate=tools['get_random_bytes']
        assert 'start with "smoke-"' in generate['description'] and 'no network call' in generate['description']
        assert generate['inputSchema']['properties']['label']['pattern']=='^smoke-[A-Za-z0-9_-]*$'
        assert tools['list_secrets']['annotations']['readOnlyHint'] is True
        args={'label':'smoke-example','n':32,'operation_id':'retryable-test-operation'}
        wrong=call(10,'tools/call',{'name':'get_random_bytes','arguments':{**args,'label':'agent-example'}})
        message=json.dumps(wrong)
        assert 'label_prefix_mismatch' in message and 'label must start with \\"smoke-\\"' in message, message
        first=call(3,'tools/call',{'name':'get_random_bytes','arguments':args})
        assert 'error' not in first and not first['result'].get('isError')
        saved=first['result']['structuredContent']
        assert saved['entropy_mode']=='local_only' and saved['bytes']==32
        secret=Path(saved['reference']).read_bytes()
        assert len(secret)==32
        repeat=call(4,'tools/call',{'name':'get_random_bytes','arguments':args})
        assert repeat['result']['structuredContent']==saved
        assert saved['format']=='raw'
        invalid=call(5,'tools/call',{'name':'get_random_bytes','arguments':{**args,'n':64}})
        assert 'error' in invalid or invalid['result'].get('isError')
        assert len(list((root/'keys').iterdir()))==1
        listing=call(6,'tools/call',{'name':'list_secrets','arguments':{}})['result']['structuredContent']
        assert listing['label_prefix']=='smoke-'
        assert [(s['label'],s['version'],s['status']) for s in listing['secrets']]==[('smoke-example',1,'saved')]
        process.stdin.close()
        process.wait(timeout=5)
        stderr=process.stderr.read()
        # Owner commands: list works piped; reveal/delete/totp-qr refuse without a terminal.
        owner=lambda *a: subprocess.run([str(binary),*a,'--config',str(path)],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=15)
        listed=owner('list')
        assert listed.returncode==0 and 'smoke-example' in listed.stdout and 'saved' in listed.stdout, listed
        assert json.loads(owner('list','--json').stdout)['secrets'][0]['label']=='smoke-example'
        refused=[owner('reveal','smoke-example'),owner('delete','smoke-example','--version','1'),owner('totp-qr','smoke-example')]
        for result in refused:
            assert result.returncode==2 and 'interactive terminal' in result.stderr, result
        assert len(list((root/'keys').iterdir()))==1
        # install: the executable installs itself (a folder with a space), then works from its new place.
        folder=root/'installed vault'
        installed=subprocess.run([str(binary),'install','--dir',str(folder),'--store','file'],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=30)
        assert installed.returncode==0 and 'new: local-only, private_file' in installed.stdout, installed
        settings=json.loads((folder/'mcp-server.json').read_text())['mcpServers']['mcpbytes-vault']
        assert json.loads((folder/'config.json').read_text())['mode']=='local_only'
        used=subprocess.run([settings['command'],'list',*settings['args']],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=30)
        assert used.returncode==0 and 'No secrets yet' in used.stdout, used
        again=subprocess.run([str(binary),'install','--dir',str(folder)],capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=30)
        assert again.returncode==0 and '(kept)' in again.stdout, again
        log=(''.join(transcript)+stderr+''.join(r.stdout+r.stderr for r in [listed,*refused])).encode()
        for pattern in [secret,secret.hex().encode(),base64.b64encode(secret),base64.urlsafe_b64encode(secret).rstrip(b'=')]:
            assert pattern not in log, 'Generated secret appeared in the helper transcript'
        assert all(json.loads(line).get('jsonrpc')=='2.0' for line in transcript)
        print('PASS: stdio initialize, tool discovery, configured description, argument errors, reference-only generation, retry, conflict, list_secrets, owner commands, install and transcript leak checks.')
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    oversized={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'x'*20000,'version':'1'}}}
    blocked=subprocess.run([str(binary),'--config',str(path)],input=json.dumps(oversized)+'\n',text=True,capture_output=True,timeout=15)
    assert '"result"' not in blocked.stdout and blocked.returncode != 0
    print('PASS: oversized MCP input is rejected before initialization.')
