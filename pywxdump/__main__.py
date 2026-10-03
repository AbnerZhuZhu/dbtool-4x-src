# -*- coding: utf-8 -*-#
# -------------------------------------------------------------------------------
# Name:         __main__.py
# Description:  让 `python -m pywxdump xxx` 和 `wxdump xxx` 等价
#               原版没有这个文件，所以 `python -m pywxdump ui` 会报
#               "No module named pywxdump.__main__"。
# -------------------------------------------------------------------------------
from .cli import console_run

if __name__ == '__main__':
    console_run()
