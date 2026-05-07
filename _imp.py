import sunpack.repair.scheduler as s
from sunpack.repair.scheduler import _lightweight_probe_candidate
print('_lightweight_probe_candidate imported OK')
print('location:', _lightweight_probe_candidate.__module__)
# Check scheduler has the diversity probe code
import inspect
src = inspect.getsource(s.RepairScheduler._run_modules)
if 'Diversity probe' in src:
    print('Diversity probe code present in _run_modules')
else:
    print('Diversity probe code MISSING from _run_modules')
if '_lightweight_probe_candidate' in src:
    print('_lightweight_probe_candidate called in _run_modules')
else:
    print('_lightweight_probe_candidate NOT called in _run_modules')
