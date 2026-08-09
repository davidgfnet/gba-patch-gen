# -*- mode: python ; coding: utf-8 -*-

# PyInstaller spec for the batch patch GUI.
#
#   pip install pyinstaller pyside6 ../tools
#   pyinstaller app.spec
#
# Produces dist/gba-patch-gui/ -- a self-contained folder (exe + _internal).
# Zip and ship it; no system Python needed on the target machine.
#
# Deliberately --onedir, not --onefile: this app spawns one worker process per
# ROM, and a onefile build re-extracts its whole ~60MB archive on every spawn.

# Qt ships a lot we never touch. Dropping these roughly halves the build.
EXCLUDE = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick", "PySide6.QtWebChannel", "PySide6.QtWebSockets",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuick3D",
    "PySide6.QtQuickWidgets", "PySide6.Qt3DCore", "PySide6.Qt3DRender",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets", "PySide6.QtBluetooth", "PySide6.QtNfc",
    "PySide6.QtPositioning", "PySide6.QtSensors", "PySide6.QtSerialPort",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtDesigner",
    "PySide6.QtHelp", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtSvgWidgets",
    "PySide6.QtNetwork", "PySide6.QtPrintSupport",
    "tkinter", "unittest", "pydoc", "doctest", "lib2to3",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    # Every patchtool submodule is imported by name via importlib, so
    # PyInstaller cannot see any of them.
    hiddenimports=[
        "patchtool",
        "patchtool.arm",
        "patchtool.generator",
        "patchtool.irq",
        "patchtool.layout",
        "patchtool.provenance",
        "patchtool.rtc",
        "patchtool.save",
        "patchtool.swi1",
        "patchtool.symmap",
        "patchtool.waitcnt",
    ],
    excludes=EXCLUDE,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="gba-patch-gui",
    console=False,      # set True to see worker tracebacks while debugging
    strip=False,
    upx=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="gba-patch-gui",
)
