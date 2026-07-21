# -*- mode: python ; coding: utf-8 -*-

analysis = Analysis(
    ['app/main.py'],
    pathex=['.'],
    binaries=[],
    datas=[('assets/provider_icons', 'provider_icons'), ('tools', 'tools'), ('rules', 'rules')],
    hiddenimports=['yara','pefile','pypdf','oletools','oletools.olevba','dkim','dkim.crypto','dkim.dnsplug','spf','dns','dns.resolver'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['fastapi', 'uvicorn', 'httpx'],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name='mailscope-engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
