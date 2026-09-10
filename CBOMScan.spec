# PyInstaller spec for the CBOMScan Python binaries.
#
# Produces two self-contained executables:
#   CBOMScan-Backend.exe  the engine: CLI + API server, spawned by the app
#   CBOMScan-Setup.exe    the setup wizard shipped in the distribution ZIP
#
# The engine's data files keep their package-relative layout so the runtime's
# Path(__file__).parent lookups (knowledge base, config, bundled CycloneDX
# schemas, React build) resolve unchanged inside the bundle.
#
# The setup wizard is deliberately built from a separate, dependency-free
# Analysis: it installs CBOMScan, so it must not carry CBOMScan with it.

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

datas = [
    ("cbomscan/knowledge_base.yaml", "cbomscan"),
    ("cbomscan/config.yaml", "cbomscan"),
    ("cbomscan/schemas", "cbomscan/schemas"),
    ("frontend/dist", "frontend/dist"),
]

# python-hcl2 parses Terraform with a Lark grammar shipped as package data
# (hcl2.lark + .lark_cache.bin). Without it hcl2.loads() raises at runtime and
# the ConfigDetector silently finds nothing in .tf files.
datas += collect_data_files("hcl2")
datas += collect_data_files("lark")

# tree-sitter grammars ship as compiled extension modules.
binaries = collect_dynamic_libs("tree_sitter_python") + collect_dynamic_libs(
    "tree_sitter_javascript"
)

hiddenimports = [
    # Lark loads its parser/lexer modules dynamically.
    *collect_submodules("lark"),
    "tree_sitter_python",
    "tree_sitter_javascript",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "cbomscan.api_server",
]

COMMON = dict(
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "numpy", "pandas", "PIL", "pytest", "IPython"],
    noarchive=False,
)

backend_analysis = Analysis(["backend_entry.py"], **COMMON)

# stdlib + tkinter only - no cbomscan, no tree-sitter, no fastapi.
setup_analysis = Analysis(
    ["installer/setup_wizard.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "cbomscan",
        "fastapi",
        "uvicorn",
        "cryptography",
        "tree_sitter",
        "yaml",
        "jsonschema",
        "cyclonedx",
        "hcl2",
        "lark",
        "matplotlib",
        "numpy",
        "pandas",
        "PIL",
        "pytest",
        "IPython",
    ],
    noarchive=False,
)

backend_pyz = PYZ(backend_analysis.pure)
setup_pyz = PYZ(setup_analysis.pure)

EXE_OPTS = dict(
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

setup_exe = EXE(
    setup_pyz,
    setup_analysis.scripts,
    setup_analysis.binaries,
    setup_analysis.datas,
    [],
    name="CBOMScan-Setup",
    console=False,
    **EXE_OPTS,
)

# console=True: the Electron main process reads this one's stdout/stderr to
# report backend startup failures, and windowsHide keeps the console invisible.
backend_exe = EXE(
    backend_pyz,
    backend_analysis.scripts,
    backend_analysis.binaries,
    backend_analysis.datas,
    [],
    name="CBOMScan-Backend",
    console=True,
    **EXE_OPTS,
)
