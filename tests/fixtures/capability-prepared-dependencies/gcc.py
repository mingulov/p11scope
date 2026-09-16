#!/usr/bin/python3
from pathlib import Path
import shutil
import sys

output = Path(sys.argv[sys.argv.index("-o") + 1])
shutil.copy2(Path(__file__).with_name("target.sh"), output)
output.chmod(0o755)
