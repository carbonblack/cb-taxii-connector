a = Analysis(['scripts/cb-taxii-connector'],
             pathex=['.'],
             hiddenimports=['unicodedata', 'requests'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='cb-taxii-connector',
          debug=False,
          strip=False,
          upx=True,
          console=True )