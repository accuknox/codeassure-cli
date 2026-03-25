# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for codeassure standalone binary

a = Analysis(
    ['build_entry.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # pydantic / pydantic-ai
        'pydantic',
        'pydantic.v1',
        'pydantic_core',
        'pydantic_ai',
        'pydantic_ai.models',
        'pydantic_ai.models.openai',
        'pydantic_ai_slim',
        # anthropic SDK
        'anthropic',
        'anthropic._client',
        'anthropic.resources',
        # httpx (used by both anthropic and pydantic-ai)
        'httpx',
        'httpcore',
        # async
        'anyio',
        'anyio._backends._asyncio',
        'sniffio',
        # openai client (pydantic-ai-slim[openai])
        'openai',
        'openai._client',
        # project internals
        'sast_verify',
        'sast_verify.cli',
        'sast_verify.config',
        'sast_verify.pipeline',
        'sast_verify.preprocess',
        'sast_verify.retrieval',
        'sast_verify.schema',
        'sast_verify.agents',
        'sast_verify.agents.analyzer',
        'sast_verify.agents.runner',
        'sast_verify.agents.tools',
        'sast_verify.agents.deps',
        'sast_verify.prompts',
        'sast_verify.prompts.analyzer',
        'sast_verify.prompts.rule_policies',
        'sast_verify.eval',
        'sast_verify.eval.evaluate',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='codeassure',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
