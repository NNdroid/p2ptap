const fs=require('fs'),path=require('path'),cp=require('child_process'),assert=require('assert/strict');
const root=fs.mkdtempSync('.openwrt-version-test-');
try {
 for(const pkg of ['p2ptap','luci-app-p2ptap']) {fs.mkdirSync(path.join(root,pkg));fs.copyFileSync('openwrt/package/'+pkg+'/Makefile',path.join(root,pkg,'Makefile'));}
 const bash=process.env.BASH_EXE || (process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
 const count=cp.execFileSync('git',['rev-list','--count','HEAD'],{encoding:'utf8'}).trim();
 for(const [input,expected] of [['v1.0.20261001','1.0.20261001'],['1.2.3','1.2.3'],['v1.0.20261003.60-abc1234','1.0.20261003.60']]) {
  const result=cp.spawnSync(bash,['scripts/set_openwrt_version.sh',input,root],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),expected);
  for(const pkg of ['p2ptap','luci-app-p2ptap']) assert.ok(fs.readFileSync(path.join(root,pkg,'Makefile'),'utf8').includes('PKG_VERSION:='+expected));
  for(const pkg of ['p2ptap','luci-app-p2ptap']) assert.ok(fs.readFileSync(path.join(root,pkg,'Makefile'),'utf8').includes('PKG_RELEASE:='+count));
  const daemon=fs.readFileSync(path.join(root,'p2ptap','Makefile'),'utf8');
  assert.ok(daemon.includes('P2PTAP_VERSION:=v'+input.replace(/^v/,'')));
  assert.ok(daemon.includes('P2PTAP_GIT_COMMIT:='+cp.execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()));
 }
 const previous=fs.readFileSync(path.join(root,'p2ptap','Makefile'),'utf8');
 for(const invalid of ['', 'v1.2.3-rc1', 'v1.2.3;echo bad', 'main', '1.2.3\n4', 'v1.0.20261003.60-abc12345']) {const result=cp.spawnSync(bash,['scripts/set_openwrt_version.sh',invalid,root],{encoding:'utf8'});assert.notEqual(result.status,0);assert.equal(fs.readFileSync(path.join(root,'p2ptap','Makefile'),'utf8'),previous);}
 const missing=cp.spawnSync(bash,['scripts/set_openwrt_version.sh','v9.9.9',root,path.join(root,'missing')],{encoding:'utf8'});
 assert.notEqual(missing.status,0);assert.equal(fs.readFileSync(path.join(root,'p2ptap','Makefile'),'utf8'),previous);
 const luci=fs.readFileSync(path.join(root,'luci-app-p2ptap','Makefile'),'utf8');assert.ok(luci.includes('PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)'));
 console.log('OpenWrt version propagation and rejection checks passed');
} finally {fs.rmSync(root,{recursive:true,force:true});}
